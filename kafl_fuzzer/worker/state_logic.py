# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Main logic used by Worker to push nodes through various fuzzing stages/mutators.
"""

import time
from typing import Any, Dict, List

from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.technique.grimoire_inference import GrimoireInference
from kafl_fuzzer.technique.redqueen.colorize import ColorizerStrategy
from kafl_fuzzer.technique.redqueen.mod import RedqueenInfoGatherer
from kafl_fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from kafl_fuzzer.technique import trim, bitflip, arithmetic, interesting_values, havoc, radamsa
from kafl_fuzzer.technique import grimoire_mutations as grimoire
from kafl_fuzzer.worker.worker import WorkerTask
from kafl_fuzzer.prpc_mutator.adapter import PRPCMutatorAdapter
#from kafl_fuzzer.technique.trim import perform_trim, perform_center_trim, perform_extend
#import kafl_fuzzer.technique.bitflip as bitflip
#import kafl_fuzzer.technique.havoc as havoc
#import kafl_fuzzer.technique.radamsa as radamsa
#import kafl_fuzzer.technique.interesting_values as interesting_values

class FuzzingStateLogic:
    HAVOC_MULTIPLIER = 4
    RADAMSA_DIV = 10
    COLORIZATION_COUNT = 1
    COLORIZATION_STEPS = 1500
    COLORIZATION_TIMEOUT = 5

    def __init__(self, worker: WorkerTask, config):
        self.worker = worker
        self.logger = self.worker.logger
        self.config = config
        self.grimoire = GrimoireInference(config, self.validate_bytes)
        havoc.init_havoc(config)
        radamsa.init_radamsa(config, self.worker.pid)

        self.stage_info = {}
        self.stage_info_start_time: float = 0
        self.stage_info_execs: float = 0
        self.stage_info_findings = 0
        self.attention_secs_start: float = 0
        self.attention_execs_start: float = 0

        self.payload2_now = None
        self.payload2_mutator = PRPCMutatorAdapter()

        # Optional external file pool for 2D fuzzing (structure-aware hints)
        self.dim2_filepool = []
        dim2_pool_path = getattr(self.config, "dim2_filepool", None)
        if dim2_pool_path:
            try:
                with open(dim2_pool_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.dim2_filepool = [line.strip().encode("utf-8") for line in f if line.strip()]
            except Exception as e:
                self.logger.warning(f"Failed to load dim2_filepool from {dim2_pool_path}: {e}")

    def __str__(self):
        return str(self.worker)

    def create_limiter_map(self, payload):
        limiter_map = bytearray([1 for _ in range(len(payload))])
        if self.config.afl_skip_range:
            for ignores in self.config.afl_skip_range:
                self.logger.debug("AFL ignore-range 0: " + str(ignores[0]) + " " + str(min(ignores[0], len(payload))))
                self.logger.debug("AFL ignore-range 1: " + str(ignores[1]) + " " + str(min(ignores[1], len(payload))))
                for i in range(min(ignores[0], len(payload)), min(ignores[1], len(payload))):
                    limiter_map[i] = 0

        return limiter_map

    def stage_timeout_reached(self, limit=20):
        if time.time() - self.stage_info_start_time > limit:
            return True
        else:
            return False

    def create_update(self, new_state, additional_data):
        ret = {}
        ret["state"] = new_state
        ret["attention_execs"] = self.stage_info_execs
        ret["attention_secs"] = time.time() - self.stage_info_start_time
        ret["state_time_initial"] = self.initial_time
        ret["state_time_havoc"] = self.havoc_time
        ret["state_time_splice"] = self.splice_time
        ret["state_time_radamsa"] = self.radamsa_time
        ret["state_time_grimoire"] = self.grimoire_time
        ret["state_time_grimoire_inference"] = self.grimoire_inference_time
        ret["state_time_redqueen"] = self.redqueen_time
        ret["performance"] = self.performance

        if additional_data:
            ret.update(additional_data)

        return ret

    def process_import(self, payload, payload2, metadata):
        self.init_stage_info(metadata)
        self.handle_import(payload, payload2, metadata)

    def process_kickstart(self, kick_len):
        metadata = {"state": {"name": "kickstart"}, "id": 0}
        self.init_stage_info(metadata)
        self.handle_kickstart(kick_len, metadata)

    def process_node(self, payload: bytes, payload2: bytes, metadata):
        self.init_stage_info(metadata)
        self.payload2_now = payload2 # 处理新node, 就在statelogic复制一份当前的文件操作
        # 不涉及payload2变异的我们就不传递payload2参数了, 用self变量对所有handler可见一个payload2
        if metadata["state"]["name"] == "initial":
            new_payload = self.handle_initial(payload, metadata)
            return self.create_update({"name": "redq/grim"}, None), new_payload
        elif metadata["state"]["name"] == "redq/grim":
            grimoire_info = self.handle_grimoire_inference(payload, metadata) # 似乎不用动, 不涉及执行，grimoire只是单纯先处理payload
            self.handle_redqueen(payload, metadata)
            return self.create_update({"name": "deterministic"}, {"grimoire": grimoire_info}), None
        elif metadata["state"]["name"] == "deterministic":
            resume, afl_det_info = self.handle_deterministic(payload, metadata)
            if resume:
                return self.create_update({"name": "deterministic"}, {"afl_det_info": afl_det_info}), None
            return self.create_update({"name": "havoc"}, {"afl_det_info": afl_det_info}), None
        elif metadata["state"]["name"] == "havoc":
            self.handle_havoc(payload, payload2, metadata)
            return self.create_update({"name": "final"}, None), None
        elif metadata["state"]["name"] == "final":
            self.handle_havoc(payload, payload2, metadata)
            return self.create_update({"name": "final"}, None), None
        else:
            raise ValueError("Unknown task stage %s" % metadata["state"]["name"])

    def init_stage_info(self, metadata, verbose=False):
        stage = metadata["state"]["name"]
        nid = metadata["id"]

        self.stage_info["stage"] = stage
        self.stage_info["parent"] = nid
        self.stage_info["method"] = "fixme"

        self.stage_info_start_time = time.time()
        self.stage_info_execs = 0
        self.attention_secs_start = metadata.get("attention_secs", 0)
        self.attention_execs_start = metadata.get("attention_execs", 0)
        self.performance = metadata.get("performance", 0)

        self.initial_time: float = 0
        self.havoc_time: float = 0
        self.splice_time: float = 0
        self.radamsa_time: float = 0
        self.grimoire_time: float = 0
        self.grimoire_inference_time: float = 0
        self.redqueen_time: float = 0

        self.worker.statistics.event_stage(stage, nid)

    def stage_update_label(self, method):
        self.stage_info["method"] = method
        self.worker.statistics.event_method(method)

    def get_parent_info(self, extra_info=None):
        info = self.stage_info.copy()
        info["parent_execs"] = self.attention_execs_start + self.stage_info_execs
        info["parent_secs"]  = self.attention_secs_start  + time.time() - self.stage_info_start_time

        if extra_info:
            info.update(extra_info)
        return info

    def handle_import(self, payload, payload2, metadata):
        # for funky targets, retry seed a couple times to avoid false negatives
        retries = 1
        if self.config.funky:
            retries = 8

        for _ in range(retries):
            _, is_new = self.execute(payload, payload2, label="import")
            if is_new: break

        # Inform user if seed yields no new coverage. This may happen if -ip0 is
        # wrong or the harness is buggy.
        if not is_new:
            self.logger.debug("Imported payload produced no new coverage, skipping..")

    def handle_kickstart(self, kick_len, metadata):
        # random injection loop to kickstart corpus with no seeds, or to scan/test a target
        busy_timeout = 5
        start_time = time.time()
        while (time.time() - start_time) < busy_timeout:
            # payload2也随机生成，反正如果针对文件系统，randbytes是不可能有作用的
            payload = rand.bytes(kick_len)
            payload2 = rand.bytes(kick_len)
            self.execute(payload, payload2, label="kickstart")

    def handle_initial(self, payload, metadata):
        time_initial_start = time.time()
        payload2 = self.payload2_now
        if self.config.trace_cb:
            self.stage_update_label("trace")
            self.worker.trace_payload(payload, payload2, metadata)

        def execute_wrapper(payload, label=None, extra_info=None):
            return self.execute(payload, payload2, label, extra_info)
        
        self.stage_update_label("calibrate")
        # Update input performance using multiple randomized executions
        # Scheduler will de-prioritize execution of very slow nodes..
        num_execs = 10
        timer_start = time.time()
        # 用闭包做，在initial阶段我们不修改technique底层策略，同时不对操作做变异（janus论述）
        havoc.mutate_seq_havoc_array(payload, execute_wrapper, num_execs)
        timer_end = time.time()
        self.performance = (timer_end-timer_start) / num_execs

        # Trimming only for stable + non-crashing inputs
        if metadata["info"]["exit_reason"] != "regular": #  or metadata["info"]["stable"]:
            self.logger.debug("Validate: Skip trimming..")
            return None

        if metadata['info']['starved']:
            return trim.perform_extend(payload, metadata, execute_wrapper, self.worker.payload_limit)

        new_payload = trim.perform_trim(payload, metadata, execute_wrapper)

        center_trim = True
        if center_trim:
            new_payload = trim.perform_center_trim(new_payload, metadata, execute_wrapper)

        self.initial_time += time.time() - time_initial_start
        if new_payload == payload:
            return None
        #self.logger.debug("before trim:\t\t{}".format(repr(payload)), self)
        #self.logger.debug("after trim:\t\t{}".format(repr(new_payload)), self)
        return new_payload

    def handle_grimoire_inference(self, payload, metadata):
        grimoire_info: Dict[Any, Any] = {}

        if not self.config.grimoire:
            return grimoire_info
        if len(metadata["new_bytes"]) <= 0 or len(payload) >= 16384:
            return grimoire_info

        self.stage_update_label("grim_infer")
        start_time = time.time()

        generalized_input = self.grimoire.generalize_input(payload, metadata)

        if generalized_input is None:
            return grimoire_info

        grimoire_info["generalized_input"] = generalized_input

        self.grimoire_inference_time = time.time() - start_time
        self.logger.debug("Grimoire generalization took %d seconds", self.grimoire_inference_time)
        self.logger.debug("Number of unique generalized inputs: %d", len(list(self.grimoire.generalized_inputs.keys())))
        return grimoire_info

    def __perform_grimoire(self, payload, metadata):
        perf = 1 / metadata["performance"]
        grimoire_input = None
        payload2 = self.payload2_now
        if "grimoire" in metadata:
            if "generalized_input" in metadata["grimoire"]:
                grimoire_input = metadata["grimoire"]["generalized_input"]

        self.stage_update_label("grim_havoc")

        def execute_wrapper(payload, label=None, extra_info=None):
            return self.execute(payload, payload2, label, extra_info)
        
        if grimoire_input:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER * 2.0)
            if len(self.grimoire.generalized_inputs) < havoc_amount / 4:
                havoc_amount = len(self.grimoire.generalized_inputs) * 2
            grimoire.havoc(tuple(grimoire_input), execute_wrapper, self.grimoire, havoc_amount, generalized=True)
        else:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER)
            if len(self.grimoire.generalized_inputs) < havoc_amount / 4:
                havoc_amount = len(self.grimoire.generalized_inputs)
            generalized_input = tuple([b''] + [bytes([c]) for c in payload] + [b''])
            grimoire.havoc(generalized_input, execute_wrapper, self.grimoire, havoc_amount, generalized=False)

    def handle_redqueen(self, payload, metadata):
        redqueen_start_time = time.time()
        payload2 = self.payload2_now
        if self.config.redqueen:
            self.__perform_redqueen(payload, payload2, metadata)
        self.redqueen_time += time.time() - redqueen_start_time

    def handle_havoc(self, payload: bytes, payload2: bytes, metadata):
        havoc_afl = True
        havoc_splice = True
        havoc_radamsa = self.config.radamsa
        havoc_grimoire = self.config.grimoire
        havoc_redqueen = self.config.redqueen

        for i in range(1):
            # Dict based on RQ learned tokens
            # TODO: AFL only has deterministic dict stage for manual dictionary.
            # However RQ dict and auto-dict actually grow over time. Perhaps
            # create multiple dicts over time and store progress in metadata?
            if havoc_redqueen: # useless
                self.__perform_rq_dict(payload, metadata)

            if havoc_grimoire:
                grimoire_start_time = time.time()
                self.__perform_grimoire(payload, metadata)
                self.grimoire_time += time.time() - grimoire_start_time

            if havoc_radamsa:
                radamsa_start_time = time.time()
                self.__perform_radamsa(payload, metadata)
                self.radamsa_time += time.time() - radamsa_start_time

            if havoc_afl:
                havoc_start_time = time.time()
                self.__perform_havoc(payload, metadata, use_splicing=False)
                self.havoc_time += time.time() - havoc_start_time

            if havoc_splice:
                splice_start_time = time.time()
                self.__perform_havoc(payload, metadata, use_splicing=True)
                self.splice_time += time.time() - splice_start_time

            if payload2:
            # 这里我们做第二维度的变异
                self.__perform_mutate_payload2(payload, payload2, metadata)

        self.logger.debug("HAVOC times: afl: %.1f, splice: %.1f, grim: %.1f, rdmsa: %.1f", self.havoc_time, self.splice_time, self.grimoire_time, self.radamsa_time)


    def validate_bytes(self, payload, metadata, extra_info=None):
        self.stage_info_execs += 1
        # FIXME: can we lift this function from worker to this class and avoid this wrapper?
        parent_info = self.get_parent_info(extra_info)
        payload2 = self.payload2_now
        return self.worker.validate_bytes(payload, payload2, metadata, parent_info)


    def execute(self, payload, payload2, label=None, extra_info=None):

        self.stage_info_execs += 1 # treat as 1 round
        if label and label != self.stage_info["method"]:
            self.stage_update_label(label)

        parent_info = self.get_parent_info(extra_info)
        bitmap, is_new = self.worker.execute(payload, payload2, parent_info)
        if is_new:
            self.stage_info_findings += 1
        return bitmap, is_new


    def execute_redqueen(self, payload, payload2):
        # one regular execution to ensure all pages cached
        # also colored payload may yield new findings(?)
        self.execute(payload, payload2)
        return self.worker.execute_redqueen(payload, payload2)


    def __get_bitmap_hash(self, payload, payload2):
        bitmap, _ = self.execute(payload, payload2)
        if bitmap is None:
            return None
        return bitmap.hash()


    def __get_bitmap_hash_robust(self, payload, payload2):
        hashes = {self.__get_bitmap_hash(payload, payload2) for _ in range(3)}
        if len(hashes) == 1:
            return hashes.pop()
        # self.logger.warn("Hash doesn't seem stable")
        return None

    # keep payload2 unchanged
    def __perform_redqueen(self, payload, payload2, metadata):
        self.stage_update_label("redq_color")

        orig_hash = self.__get_bitmap_hash_robust(payload, payload2)
        extension = bytes([207, 117, 130, 107, 183, 200, 143, 154])
        appended_hash = self.__get_bitmap_hash_robust(payload + extension, payload2)

        if orig_hash and orig_hash == appended_hash:
            self.logger.debug("Redqueen: Input can be extended")
            payload_array = bytearray(payload + extension)
        else:
            payload_array = bytearray(payload)

        colored_alternatives = self.__perform_coloring(payload_array, payload2)
        if colored_alternatives:
            payload_array = colored_alternatives[0]
            assert isinstance(colored_alternatives[0], bytearray), print(
                    "!! ColoredAlternatives:", repr(colored_alternatives[0]), type(colored_alternatives[0]))
        else:
            self.logger.debug("Redqueen: Input is not stable, skipping..")
            return

        self.stage_update_label("redq_trace")
        rq_info = RedqueenInfoGatherer()
        rq_info.make_paths(RedqueenWorkdir(self.worker.pid, self.config))
        for pld in colored_alternatives:
            if self.execute_redqueen(pld, payload2):
                rq_info.get_info(pld)

        rq_info.get_proposals()
        self.stage_update_label("redq_mutate")

        def execute_wrapper(payload, label=None, extra_info=None):
            return self.execute(payload, payload2, label, extra_info)
        rq_info.run_mutate_redqueen(payload_array, execute_wrapper)

        #if self.mode_fix_checksum:
        #    for addr in rq_info.get_hash_candidates():
        #        self.redqueen_state.add_candidate_hash_addr(addr)

        # for addr in rq_info.get_boring_cmps():
        #    self.redqueen_state.blacklist_cmp_addr(addr)
        # self.redqueen_state.update_redqueen_blacklist(RedqueenWorkdir(0))


    def dilate_effector_map(self, effector_map, limiter_map):
        ignore_limit = 2
        effector_map[0] = 1
        effector_map[-1] = 1
        for i in range(len(effector_map) // ignore_limit):
            base = i * ignore_limit
            effector_slice = effector_map[base:base + ignore_limit]
            limiter_slice = limiter_map[base:base + ignore_limit]
            if any(effector_slice) and any(limiter_slice):
                for j in range(len(effector_slice)):
                    effector_map[i + j] = 1

    def handle_deterministic(self, payload, metadata):
        payload2 = self.payload2_now
        if self.config.afl_dumb_mode:
            return False, {}

        skip_zero = self.config.afl_skip_zero
        arith_max = self.config.afl_arith_max
        use_effector_map = not self.config.afl_no_effector and len(payload) > 128
        limiter_map = self.create_limiter_map(payload)
        effector_map = None

        def execute_wrapper(payload, label=None, extra_info=None):
            return self.execute(payload, payload2, label, extra_info)
        
        # Mutable payload allows faster bitwise manipulations
        payload_array = bytearray(payload)
        
        default_info = {"stage": "flip_1"}
        det_info = metadata.get("afl_det_info", default_info)

        # Walking bitflips
        if det_info["stage"] == "flip_1":
            bitflip.mutate_seq_walking_bits(payload_array,      execute_wrapper, skip_null=skip_zero, effector_map=limiter_map)
            bitflip.mutate_seq_two_walking_bits(payload_array,  execute_wrapper, skip_null=skip_zero, effector_map=limiter_map)
            bitflip.mutate_seq_four_walking_bits(payload_array, execute_wrapper, skip_null=skip_zero, effector_map=limiter_map)

            det_info["stage"] = "flip_8"
            if self.stage_timeout_reached():
                return True, det_info

        # Walking byte sets..
        if det_info["stage"] == "flip_8":
            # Generate AFL-style effector map based on walking_bytes()
            if use_effector_map:
                self.logger.debug("Preparing effector map..")
                effector_map = bytearray(limiter_map)

            bitflip.mutate_seq_walking_byte(payload_array, execute_wrapper, skip_null=skip_zero, limiter_map=limiter_map, effector_map=effector_map)

            if use_effector_map:
                self.dilate_effector_map(effector_map, limiter_map)
            else:
                effector_map = limiter_map

            bitflip.mutate_seq_two_walking_bytes(payload_array,  execute_wrapper, effector_map=effector_map)
            bitflip.mutate_seq_four_walking_bytes(payload_array, execute_wrapper, effector_map=effector_map)

            det_info["stage"] = "arith"
            if effector_map:
                det_info["eff_map"] = bytearray(effector_map)
            if self.stage_timeout_reached():
                return True, det_info

        # Arithmetic mutations..
        if det_info["stage"] == "arith":
            effector_map = det_info.get("eff_map", None)
            arithmetic.mutate_seq_8_bit_arithmetic(payload_array,  execute_wrapper, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            arithmetic.mutate_seq_16_bit_arithmetic(payload_array, execute_wrapper, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            arithmetic.mutate_seq_32_bit_arithmetic(payload_array, execute_wrapper, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)

            det_info["stage"] = "intr"
            if self.stage_timeout_reached():
                return True, det_info

        # Interesting value mutations..
        if det_info["stage"] == "intr":
            effector_map = det_info.get("eff_map", None)
            interesting_values.mutate_seq_8_bit_interesting(payload_array, execute_wrapper, skip_null=skip_zero, effector_map=effector_map)
            interesting_values.mutate_seq_16_bit_interesting(payload_array, execute_wrapper, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            interesting_values.mutate_seq_32_bit_interesting(payload_array, execute_wrapper, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)

            det_info["stage"] = "done"

        return False, det_info


    def __perform_rq_dict(self, payload_array, metadata):
        payload2 = self.payload2_now
        rq_dict = havoc.get_redqueen_dict()
        counter = 0
        seen_addr_to_value = havoc.get_redqueen_seen_addr_to_value()
        if len(payload_array) < 256: # 我们用不到了，256字节的输入非常少
            for addr in rq_dict:
                for repl in rq_dict[addr]:
                    if addr in seen_addr_to_value and (
                            len(seen_addr_to_value[addr]) > 32 or repl in seen_addr_to_value[addr]):
                        continue
                    if not addr in seen_addr_to_value:
                        seen_addr_to_value[addr] = set()
                    seen_addr_to_value[addr].add(repl)
                    self.logger.debug("RQ-Dict: attempting %s ", repr(repl))
                    for apply_dict in [havoc.dict_insert_sequence, havoc.dict_replace_sequence]:
                        for i in range(len(payload_array)-len(repl)):
                            counter += 1
                            mutated = apply_dict(payload_array, repl, i)
                            self.execute(mutated, payload2, label="redq_dict")
        self.logger.debug("RedQ-Dict: Have performed %d iters", counter)


    def __perform_radamsa(self, payload_array, metadata):
        payload2 = self.payload2_now
        perf = metadata["performance"]
        radamsa_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER/perf) // self.RADAMSA_DIV

        def execute_wrapper(payload, label=None, extra_info=None):
            return self.execute(payload, payload2, label, extra_info)
        
        self.stage_update_label("radamsa")
        radamsa.mutate_seq_radamsa_array(payload_array, execute_wrapper, radamsa_amount)

    def __perform_havoc(self, payload_array: bytes, metadata, use_splicing):
        payload2 = self.payload2_now
        perf = metadata["performance"]
        havoc_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER / perf)

        def execute_wrapper(payload, label=None, extra_info=None):  
            return self.execute(payload, payload2, label, extra_info)
        if use_splicing:
            self.stage_update_label("afl_splice")
            havoc.mutate_seq_splice_array(payload_array, execute_wrapper, havoc_amount)
        else:
            self.stage_update_label("afl_havoc")
            havoc.mutate_seq_havoc_array(payload_array, execute_wrapper, havoc_amount)


    def __check_colorization(self, orig_hash, payload_array, payload2, min, max):
        backup = payload_array[min:max]
        for i in range(min, max):
            payload_array[i] = rand.int(255)
        new_hash = self.__get_bitmap_hash(payload_array, payload2)
        if new_hash is not None and new_hash == orig_hash:
            return True
        else:
            payload_array[min:max] = backup
            return False

    def __colorize_payload(self, orig_hash, payload_array, payload2):
        def checker(min_i, max_i):
            self.__check_colorization(orig_hash, payload_array, payload2, min_i, max_i)

        c = ColorizerStrategy(len(payload_array), checker)
        t = time.time()
        i = 0
        while True:
            if i >= FuzzingStateLogic.COLORIZATION_STEPS and time.time() - t > FuzzingStateLogic.COLORIZATION_TIMEOUT:  # TODO add to config
                break
            if len(c.unknown_ranges) == 0:
                break
            c.colorize_step()
            i += 1


    def __perform_coloring(self, payload_array, payload2):
        self.logger.debug("Redqueen: Initial colorize...")
        orig_hash = self.__get_bitmap_hash_robust(payload_array, payload2)
        if orig_hash is None:
            return None

        colored_arrays: List[Any] = []
        for i in range(FuzzingStateLogic.COLORIZATION_COUNT):
            if len(colored_arrays) >= FuzzingStateLogic.COLORIZATION_COUNT:
                assert False  # TODO remove me
            tmpdata = bytearray(payload_array)
            self.__colorize_payload(orig_hash, tmpdata, payload2)
            new_hash = self.__get_bitmap_hash(tmpdata, payload2)
            if new_hash is not None and new_hash == orig_hash:
                colored_arrays.append(tmpdata)
            else:
                return None

        colored_arrays.append(payload_array)
        return colored_arrays

    def __perform_mutate_payload2(self, payload, payload2, metadata):
        # Skip if no payload2 is present
        if not payload2:
            return

        perf = metadata["performance"]
        havoc_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER / perf)

        # Extract filesystem paths from payload2 for mutation pool
        try:
            calls = self.payload2_mutator.parse(payload2)
            # Seed mutator pathpool with external hints + observed paths
            if self.dim2_filepool:
                base_pool = list(self.dim2_filepool)
                if self.payload2_mutator.pathpool:
                    base_pool.extend(self.payload2_mutator.pathpool)
                self.payload2_mutator.pathpool = list(dict.fromkeys(base_pool))

            self.payload2_mutator.update_pathpool(calls)
        except Exception as e:
            self.logger.warning(f"Failed to parse payload2: {e}")
            return

        self.stage_update_label("payload2_havoc")

        for _ in range(havoc_amount):
            try:
                # Mutate payload2 and execute with current payload1
                mutated_payload2 = self.payload2_mutator.mutate(payload2, num_mutations=1)
                self.execute(payload, mutated_payload2, label="payload2_havoc")
            except Exception as e:
                self.logger.debug(f"Payload2 mutation failed: {e}")
                continue