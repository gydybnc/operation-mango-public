from ast import Or
from angr import Project,SimProcedure
import pyvex  
import networkx as nx
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
import claripy
import angr
import itertools
from typing import Optional, Tuple, Set, List, Type, Union
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, SpOffset
from claripy import BVV, BVS, Or
from angr.analyses.analysis import AnalysisFactory
from angr.analyses.reaching_definitions.call_trace import CallTrace
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.analyses.reaching_definitions.reaching_definitions import (
    ReachingDefinitionsAnalysis,
)
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from argument_resolver.handlers.base import HandlerBase
from typing import TYPE_CHECKING, List, Set, Optional, Tuple
import logging

from cle import Symbol

l = logging.getLogger(__name__)
from argument_resolver.external_function.function_declarations import CUSTOM_DECLS
from argument_resolver.external_function.sink import Sink, VULN_TYPES
from argument_resolver.formatters.closure_formatter import ClosureFormatter
from argument_resolver.formatters.log_formatter import make_logger
from argument_resolver.handlers import (
    NVRAMHandlers,
    NetworkHandlers,
    StdioHandlers,
    StdlibHandlers,
    StringHandlers,
    UnistdHandlers,
    URLParamHandlers,
    handler_factory,
)
from argument_resolver.utils.rda import CustomRDA
import capstone
from argument_resolver.utils.calling_convention import CallingConventionResolver
from angr.analyses.reaching_definitions.function_handler import FunctionHandler

from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
import signal

class TimeoutException(Exception): pass

def timeout_handler(signum, frame):
    raise TimeoutException()

tag_values = {
    "env": 0.7,
    "file": 0.5,
    "argv": 0.4,
    "network": 0.6,
    "unknown": 0,
}

categories = {
    "env": ["env", "getenv", "nvram", "frontend_param", "getvalue"],
    "file": ["fopen", "read", "open", "fread", "fgets", "stdin"],
    "argv": ["argv"],
    "network": ["socket", "accept", "recv", "nflog_get_payload"],
    "unknown": ["unknown"],
}



def get_value_from_source(tag):
    func = tag.split("(")[0].lower()
    func = "nvram" if "nvram" in func else func
    func = "recv" if "recv" in func else func
    for category, funcs in categories.items():
        if func in funcs:
            return tag_values[category]
    return 0


def get_rank(sources):
    return {source: get_value_from_source(source) for source in sources}


class ArrayAccessSinkDetector:
    def __init__(self, project):
        self.project = project
        self.sinks = []
        self._reg_map = self._build_reg_map()
    
    
    def _build_reg_map(self):
        reg_map = {}
        for reg in self.project.arch.register_list:
            # 使用 archinfo 的 vex_offset 属性（与 VEX 内部偏移一致）
            if reg.vex_offset is not None:
                if reg.vex_offset not in reg_map or reg.size == self.project.arch.bits // 8:
                    reg_map[reg.vex_offset] = reg.name
        return reg_map

    def detect_sinks(self):
        cfg = self.project.analyses.CFGFast()
        for func in cfg.functions.values():
            if func.addr < 0x400000 or func.addr >=0x4FFFFF:
                continue
            for block in func.blocks:
                self._analyze_block(block)

    def _analyze_block(self, block):
        irsb = self.project.factory.block(block.addr).vex
        # 构建临时变量映射表
        tmp_exprs = {}
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                tmp_exprs[stmt.tmp] = stmt.data

        stmt_insn_map = self._build_stmt_insn_map(irsb)

        for stmt_idx, stmt in enumerate(irsb.statements):
            if isinstance(stmt, pyvex.IRStmt.Store):
                try:
                    self._analyze_memory_access(irsb, stmt, stmt_idx, stmt_insn_map, tmp_exprs)
                except Exception as e:
                    print(e)
            if isinstance(stmt, pyvex.IRStmt.Put):
                try:
                    self._analyze_register_write(irsb, stmt, stmt_idx, stmt_insn_map, tmp_exprs)
                except Exception as e:
                    print(e)

    def _build_stmt_insn_map(self, irsb):
        stmt_insn_map = []
        current_insn = 0
        for s in irsb.statements:
            if isinstance(s, pyvex.IRStmt.IMark):
                current_insn += 1
            stmt_insn_map.append(current_insn - 1)
        return stmt_insn_map

    def _analyze_register_write(self, irsb, stmt, stmt_idx, stmt_insn_map, tmp_exprs):
        insn_idx = stmt_insn_map[stmt_idx] if stmt_idx < len(stmt_insn_map) else -1
        addr = irsb.instruction_addresses[insn_idx] if insn_idx != -1 else "UNKNOWN"

        if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
            index_info = self._trace_index_expression(stmt.data, tmp_exprs)
            if not index_info:
                return

            reg_offset = stmt.offset
            reg_name = self._reg_map.get(reg_offset, f"unk_{reg_offset}")

            print(f"\n📝 检测到寄存器写入 @ {hex(addr) if isinstance(addr, int) else addr}")
            print(f"  写入寄存器: {reg_name}")
            print(f"  值来源表达式: {self._pp_expr(stmt.data)}")
            print(f"  索引类型: {index_info['type']}")
            print(f"  寄存器链条: {index_info['reg_chain']}")
            self.sinks.append((addr, index_info))

    def _analyze_memory_access(self, irsb, stmt, stmt_idx, stmt_insn_map, tmp_exprs):
        insn_idx = stmt_insn_map[stmt_idx] if stmt_idx < len(stmt_insn_map) else -1
        addr = irsb.instruction_addresses[insn_idx] if insn_idx != -1 else "UNKNOWN"
        
        if isinstance(stmt.addr, pyvex.IRExpr.RdTmp):
           # if(stmt.addr.tmp == 9):
                #breakpoint()
            index_info = self._trace_index_expression(stmt.addr, tmp_exprs)
            if not index_info:
                return

            print(f"\n🔥 检测到数组访问 @ {hex(addr) if isinstance(addr, int) else addr}")
            print(f"  内存表达式: {self._pp_expr(stmt.addr)}")
            print(f"  索引类型: {index_info['type']}")
            print(f"  寄存器链条: {index_info['reg_chain']}")
            self.sinks.append((addr, index_info))

    def _trace_index_expression(self, expr, tmp_exprs):
        result = {
            'type': None,
            'reg_chain': [],
            'scale': 1
        }
        
        def _walk(e):
            if isinstance(e, pyvex.IRExpr.RdTmp):
                if e.tmp in tmp_exprs:
                    return _walk(tmp_exprs[e.tmp])
                return False

            if isinstance(e, pyvex.IRExpr.Get):
                reg_name = self._reg_map.get(e.offset, f'unk_{e.offset}') 
                result['reg_chain'].append(reg_name)
                return True

            if isinstance(e, pyvex.IRExpr.Binop):
                if e.op.startswith('Iop_Add') or e.op.startswith('Iop_Sub'):
                    left_has_reg = _walk(e.args[0])
                    right_has_reg = _walk(e.args[1])
                    if left_has_reg and right_has_reg:
                        result['type'] = '基地址+索引'
                    return left_has_reg or right_has_reg
                elif e.op.startswith('Iop_Shl'):
                    base_has_reg = _walk(e.args[0])
                    if isinstance(e.args[1], pyvex.IRExpr.Const):
                        result['scale'] = 1 << e.args[1].con.value
                    return base_has_reg

            if isinstance(e, pyvex.IRExpr.Unop):
                if any(keyword in e.op for keyword in ('Sto', 'to', 'Uto')):
                    return _walk(e.args[0])
                '''                
                if   e.op.startswith ('Iop_32Sto64') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_64Sto32') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_64to32') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_32to64') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_32to8') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_8to32') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_1Uto32') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_1Uto16') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_8Uto32') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_8Uto64') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_16Uto32') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_32Uto16') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_32Uto64') :
                    return _walk(e.args[0])
                elif e.op.startswith ('Iop_64Uto32') :
                    return _walk(e.args[0])
                '''
                print(f'unsupported Unop: {e.op}')
                return False

            if isinstance(e, pyvex.IRExpr.Load):
                return _walk(e.addr)
            
            return False

        _walk(expr)
        return result if result['type'] else None

    def _pp_expr(self, expr):
        if isinstance(expr, pyvex.IRExpr.Binop):
            return f"({self._pp_expr(expr.args[0])} {expr.op[4:]} {self._pp_expr(expr.args[1])})"
        if isinstance(expr, pyvex.IRExpr.Get):
            return self._reg_map.get(expr.offset, f'unk_{expr.offset}')
        if isinstance(expr, pyvex.IRExpr.RdTmp):
            return f"t{expr.tmp}"
        if isinstance(expr, pyvex.IRExpr.Const):
            return hex(expr.con.value)
        return str(expr)


class TaintTracer:
    def __init__(self, project, detector):
        self.project = project
        self.detector = detector
        self.cfgE = self.project.analyses.CFGEmulated(
                            keep_state=True,
                            state_add_options=angr.sim_options.refs,
                            context_sensitivity_level=2
                                                        )
        self.project.analyses.CompleteCallingConventions(
            recover_variables=True,  # 恢复变量
            analyze_callsites=True,  # 分析调用点
            workers=1           # 多线程加速
        )
        #self.RDA = AnalysisFactory(self.project, CustomRDA)
        #print(x.name for x in self.project.kb.functions.values())
        self.cc_resolver = CallingConventionResolver(
            project=self.project,
            arch=self.project.arch,
            functions=self.project.kb.functions
        )
        self.temp_codeloc:CodeLocation
        self.results = {
            'param_sinks': [],
            'tainted_sinks': []
        }
        self.Handler = handler_factory(
            [
                StdioHandlers,
                StdlibHandlers,
                StringHandlers,
                UnistdHandlers,
                NVRAMHandlers,
                NetworkHandlers,
                URLParamHandlers,
            ]
        )

    def trace_sinks(self):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(1000)  # 限制 10 秒
        for sink_addr, index_info in self.detector.sinks:
            # 获取函数上下文
        
            func = self.project.kb.functions.floor_func(sink_addr)
            #print(func)
            if not func:  
                continue
            try:
                # 参数关联性检查
                self._check_parameter_origin(func, index_info, sink_addr)

                if self.results['param_sinks']:
                    continue  # 参数相关优先
            except Exception:
                pass
            # 内部污点检查
            try:
                self._check_internal_taint(func, sink_addr)
            except TimeoutException:
                print("[!] explore 超时中止")


        return self.results

    def _check_parameter_origin(self, func, index_info, sink_addr):
        # 获取调用约定
        if func.calling_convention is None:
            func.calling_convention = self.cc_resolver.get_cc(
                func.name
            )
            if hasattr(func.calling_convention, "sim_func"):
                func.prototype = func.calling_convention.sim_func

        if func.prototype is None:
            function.prototype = self._calling_convention_resolver.get_prototype(
                function.name
            )
            
        cc = func.calling_convention
        if cc is None:
            print(f"无法获取函数 {func.name} 的调用约定")
            return None
        
        # 提取参数寄存器列表
        param_regs = func.calling_convention.ARG_REGS
        print(f"[DEBUG] 函数 {func.name} 参数寄存器: {param_regs}")
        handler = StdioHandlers(self.project)
        observation_point = ('insn', sink_addr, OP_BEFORE)

        rda = self.project.analyses.ReachingDefinitions(subject = func, 
                                        observation_points=[observation_point],
                                        function_handler = handler,
                                        dep_graph=DepGraph())

        state_before_sink = rda.observed_results[observation_point]
        reg_name = self._reg_tract(func,sink_addr)

        reg_offset = self.project.arch.registers[reg_name][0]

        reg_def = list(state_before_sink.get_register_definitions(reg_offset,4))[0]
        self.temp_codeloc = reg_def.codeloc
        relat_G = rda.dep_graph.transitive_closure(reg_def)
        import re

        parameter_regs = []  # 用于保存满足条件的寄存器序号

        for node in relat_G.nodes():
            if hasattr(node, "tags") and node.tags is not None:
                # 将所有 Tag 转换为字符串后判断是否有 'ParameterTag'
                if any("ParameterTag" in str(tag) for tag in node.tags):
                # Atom 的字符串格式类似 "<Reg 72<8>>" 或 "<Reg rax<8>>"
                    atom_str = str(node.atom)
                    m = re.search(r"Reg\s+(\d+)", atom_str)
                    if m:
                        reg_num = int(m.group(1))
                        parameter_regs.append(reg_num)
                    else:
                        m2 = re.search(r"Reg\s+(\S+)<", atom_str)
                        if m2:
                                    _ = m2.group(1)
                                    parameter_regs.append(_)
        
        if len(parameter_regs) == 0:
            return None

        for num in parameter_regs:
            for _ in param_regs:
                if self.project.arch.registers[_][0] == num:
                    self.results['param_sinks'].append(self._build_param_result(func, sink_addr, _, param_regs))
                    
        return None
        '''
        except Exception as e:
            print(f"参数分析异常: {str(e)}")
            return None
        '''
    def _reg_tract(self, func, sink_addr):
        arch = self.project.arch
        if arch.name.startswith("ARM"):
            if arch.bits == 64:
                cs_arch = capstone.CS_ARCH_ARM64
                cs_mode = capstone.CS_MODE_ARM
            else:
                cs_arch = capstone.CS_ARCH_ARM
                cs_mode = capstone.CS_MODE_ARM  
        elif arch.name.startswith("X86") or arch.name.startswith("AMD64") or arch.name.startswith("i386"):
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64 if arch.bits == 64 else capstone.CS_MODE_32
        elif arch.name.startswith("MIPS"):
            cs_arch = capstone.CS_ARCH_MIPS
            if arch.endness == "Iend_BE":
                cs_mode = capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN
            else:
                cs_mode = capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN
        else:
            raise Exception("Unsupported architecture: " + arch.name)
        
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True  # 打开详细模式
        block = self.project.factory.block(sink_addr)
        reg_name = None  # 默认返回值

        for insn in md.disasm(block.bytes, block.addr):
            if insn.address == sink_addr:
                for op in insn.operands:
                    # x86
                    if cs_arch == capstone.CS_ARCH_X86 and op.type == capstone.x86.X86_OP_MEM:
                        mem = op.mem
                        reg_name = insn.reg_name(mem.index) if mem.index != 0 else insn.reg_name(mem.base)
                        print("X86 memory operand register:", reg_name)

                    # ARM / ARM64
                    elif cs_arch in (capstone.CS_ARCH_ARM, capstone.CS_ARCH_ARM64) and op.type == capstone.arm.ARM_OP_MEM:
                        mem = op.mem
                        reg_name = insn.reg_name(mem.index) if mem.index != 0 else insn.reg_name(mem.base)
                        print("ARM memory operand register:", reg_name)

                    # MIPS
                    elif cs_arch == capstone.CS_ARCH_MIPS and op.type == capstone.mips.MIPS_OP_MEM:
                        mem = op.mem
                        reg_name = insn.reg_name(mem.base)
                        print("MIPS base register:", reg_name)
                break

        return reg_name

    def _extract_parameter_regs(self, cc):
        """从 SimCC 对象提取寄存器名"""
        regs = set()
        
        if hasattr(cc, "ARG_REGS"):
            regs.update(cc.ARG_REGS) 
        
        #  动态调用 arg_locs 方法（如果存在）
        elif hasattr(cc, "arg_locs") and callable(cc.arg_locs):
            # 调用 arg_locs() 方法获取参数位置列表
            arg_locs = cc.arg_locs()
            for arg in arg_locs:
                # 检查参数是否是寄存器类型（如 SimRegArg 对象）
                if hasattr(arg, "reg_name"):
                    regs.add(arg.reg_name)
                elif isinstance(arg, str):
                    regs.add(arg)
        
        return regs

    def _build_param_result(self, func, sink_addr, reg, param_regs):
        """构造标准化结果"""
        try:
            param_index = list(param_regs).index(reg)
        except ValueError:
            param_index = -1

        return {
            'type': 'parameter',
            'func_name': func.name,
            'func_addr': hex(func.addr),
            'sink_addr': hex(sink_addr),
            'param_reg': reg,
            'param_index': param_index
        }

    def _check_step_limit(self, simgr, max_steps, step_counter):
        step_counter[0] += 1  # Increment the step counter each time this function is called
        if step_counter[0] >= max_steps:
            return True  # Stop stepping if max_steps reached
        return False

    def _check_internal_taint(self, func, sink_addr):

        self._hook_input()
        state = self.project.factory.blank_state(
            addr=func.addr,
            add_options={
                angr.options.SYMBOLIC,
                angr.options.LAZY_SOLVES,
                angr.options.TRACK_CONSTRAINTS
            }
        )
        state.options.add(angr.options.SYMBOLIC)
        simgr = self.project.factory.simulation_manager(state)
        simgr.explore(find=sink_addr)

        if simgr.found:
            for found_state in simgr.found:
                print(f"到达目标地址 {hex(sink_addr)} 通过状态 {found_state}")
                
                # 精确指令级分析
                insn = found_state.project.factory.block(found_state.addr).capstone.insns[0]
                print(f"分析指令: {insn.mnemonic} {insn.op_str}")

                # 检查操作数污染
                for op in insn.operands:
                    if op.type == capstone.CS_OP_REG:
                        _ = self._check_register_taint(found_state, insn, op, sink_addr)
                    elif op.type == capstone.CS_OP_MEM:
                        _ = self._check_memory_taint(found_state, op, sink_addr)
                if _ == True:
                    _path = found_state.history.bbl_addrs
                    self.results['tainted_sinks'].append(
                        {
                        'func_addr': hex(func.addr),
                        'trace': [hex(addr) for addr in _path],
                        'sink_addr': hex(sink_addr),
                        }
                    )
        self._unhook_input()
        return simgr.found

    def _hook_input(self):
        hook_map = {
            "fopen": myHooklib.HookedFopen(),
            "open": myHooklib.HookedOpen(),
            "read": myHooklib.HookedRead(),
            "fread": myHooklib.HookedFread(),
            "fgets": myHooklib.HookedFgets(),
            "strtol": myHooklib.HookedStrtol(),
            "fwrite": myHooklib.HookedFWrite(),
            "getenv": myHooklib.HookedEnvGetter(),
            "env": myHooklib.HookedEnvGetter(),
            "nvram_get": myHooklib.HookedEnvGetter(),  
            "frontend_param": myHooklib.HookedEnvGetter(),
            "getvalue": myHooklib.HookedEnvGetter(),
        }
        for name, hook in hook_map.items():
            try:
                self.project.hook_symbol(name, hook)
                print(f"[+] Hooked symbol: {name}")
            except Exception:
                print(f"[~] Symbol not found: {name} (skipped)")

    def _unhook_input(self):
        symbol_names = [
        "fopen", "open", "read", "fread",
        "fgets", "strtol", "fwrite","getenv",
        "env","nvram_get","frontend_param","getvalue"
        ]
        for sym in symbol_names:
            symbol_obj = self.project.loader.find_symbol(sym)
            if symbol_obj is None:
                print(f"[!] Symbol not found: {sym}")
                continue

            addr = symbol_obj.rebased_addr
            if addr in self.project._sim_procedures:
                self.project.unhook(addr)
                print(f"[-] Unhooked {sym} at 0x{addr:x}")
            else:
                print(f"[~] Symbol {sym} not hooked; skipping")

    def _check_register_taint(self, state, insn, op, sink_addr):
        reg_name = insn.reg_name(op.reg)
        reg_val = getattr(state.regs, reg_name)
        if state.solver.symbolic(reg_val):
            print(f"寄存器 {reg_name} 被符号输入影响")
            return True
        else:
            return None
    def _check_memory_taint(self, state, op, sink_addr):
        try:
            addr = state.solver.eval(op.mem.disp)
            mem_val = state.memory.load(addr, op.size)
            if state.solver.symbolic(mem_val):
                print(f"内存地址 {hex(addr)} 被污染")
                return True
            else:
                return None
        except Exception as e:
            print(f"内存访问错误: {str(e)}")
            return None
    


class myHooklib:
    # fopen(const char *pathname, const char *mode)
    class HookedFopen(SimProcedure):
        def run(self, pathname, mode):
            fake_file_ptr = 0x12345678  # 任意假的 FILE* 指针
            return self.state.solver.BVV(fake_file_ptr, self.state.arch.bits)

    # open(const char *pathname, int flags)
    class HookedOpen(SimProcedure):
        def run(self, pathname, flags, mode=None):
            fake_fd = self.state.solver.BVV(3, self.state.arch.bits)  # 假的 fd，0/1/2 是 stdin/out/err
            return fake_fd
            
    # read(int fd, void *buf, size_t count)
    class HookedRead(SimProcedure):
        def run(self, fd, buf, count):
            state = self.state

            read_len = state.solver.eval(count) if not state.solver.symbolic(count) else 50
            sym_read = BVS("read_input", 8 * read_len)

            state.memory.store(buf, sym_read)
            return BVV(read_len, state.arch.bits)

    # fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
    class HookedFread(SimProcedure):
        def run(self, ptr, size, nmemb, stream):
            state = self.state
            total = size * nmemb
            read_len = state.solver.eval(total) if not state.solver.symbolic(total) else 50
            sym_data = BVS("fread_input", 8 * read_len)

            state.memory.store(ptr, sym_data)
            return BVV(nmemb, state.arch.bits)

    class HookedFgets(SimProcedure):
        def run(self, s_ptr, n, stream):
            state = self.state

            # 默认最大读取字节数（处理符号化的n）
            if state.solver.symbolic(n):
                n_val = 100
            else:
                n_val = state.solver.eval(n)

            # 生成符号输入: n-1字节 + null结尾
            input_len = n_val - 1
            input_sym = BVS("fgets_input", 8 * input_len)

            state.memory.store(s_ptr, input_sym)
            state.memory.store(s_ptr + input_len, BVV(0, 8))  # Null terminator

            return s_ptr  # fgets 返回缓冲区地址

    class HookedStrtol(SimProcedure):
        def run(self, nptr, endptr, base):
            state = self.state

            # 修正 base 值
            if state.solver.symbolic(base):
                state.add_constraints(Or(base >= 2, base <= 36))
                base_val = 10
            else:
                base_val = state.solver.eval(base)
                if not (2 <= base_val <= 36):
                    base_val = 10

            # 返回一个符号化整数（模拟 strtol 返回值）
            ret_val = BVS("strtol_ret", state.arch.bits)

            # 可加额外约束：限制值范围（可选）
            state.add_constraints(ret_val >= -100000, ret_val <= 100000)

            return ret_val
    
    class HookedFWrite(SimProcedure):
        def run(self, ptr, size, nmemb, stream):
            # 计算总写入量（处理符号值情况）
            total_bytes = size * nmemb
            
            # 约束写入量为合理范围
            if self.state.solver.symbolic(total_bytes):
                self.state.add_constraints(
                    total_bytes <= 1024,  # 限制最大写入量
                    action="fwrite_size_limit"
                )
            
            # 返回成功写入量（不实际操作内存）
            return self.state.solver.If(
                total_bytes == 0, 
                0,  # 写入失败
                nmemb  # 返回请求的nmemb（简化处理）
            )
    
    class HookedEnvGetter(SimProcedure):
        def run(self, name):
            state = self.state
            maxlen = 64

            key_str = state.mem[name].string.concrete if state.solver.symbolic(name) == False else "symbolic_key"
            sym_val = BVS(f"{key_str}_env_val", maxlen * 8)
            val_addr = state.heap.allocate(maxlen)

            state.memory.store(val_addr, sym_val)
            state.memory.store(val_addr + maxlen - 1, claripy.BVV(0, 8))  # null terminator

            return val_addr

if __name__ == "__main__":
    project = Project("./arraytest", auto_load_libs=False)
    detector = ArrayAccessSinkDetector(project)
    detector.detect_sinks()
    
    tracer = TaintTracer(project, detector)
    results = tracer.trace_sinks()

    print("\n分析结果摘要:")
    if not results['param_sinks'] and not results['tainted_sinks']:
        print("未发现高风险点")
    
    for item in results['param_sinks']:
        print(f"[参数风险] 函数 {item['func_addr']} 参数#{item['param_index']} ({item['param_reg']}) -> {item['sink_addr']}")
    
    for item in results['tainted_sinks']:
        print(f"[内部污染] 函数 {item['func_addr']} 源头:{item['trace']} -> {item['sink_addr']}")
        