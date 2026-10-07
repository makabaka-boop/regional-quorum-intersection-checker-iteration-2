import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from copy import deepcopy
from itertools import combinations, permutations
from pathlib import Path

import pytest

from quorum.analyzer import ValidationError, analyze
from quorum.server import build_server

ROOT = Path(__file__).resolve().parents[1]


def replica(identifier, weight=1, dc="A", online=True):
    return {
        "id": identifier,
        "weight": weight,
        "datacenter": dc,
        "online": online,
    }


def make_payload(replicas, read_threshold=0, write_threshold=0,
                 read_dcs=None, write_dcs=None):
    return {
        "replicas": replicas,
        "read": {
            "weight_threshold": read_threshold,
            "required_datacenters": read_dcs or [],
        },
        "write": {
            "weight_threshold": write_threshold,
            "required_datacenters": write_dcs or [],
        },
    }


def feasible_masks_brute(payload):
    replicas = sorted(payload["replicas"], key=lambda item: item["id"])
    n = len(replicas)

    def side_masks(side):
        required = set(side["required_datacenters"])
        result = []
        for mask in range(1 << n):
            selected = [
                replicas[i]
                for i in range(n)
                if mask & (1 << i)
            ]
            if any(not item["online"] for item in selected):
                continue
            if sum(item["weight"] for item in selected) < side["weight_threshold"]:
                continue
            if not required.issubset({item["datacenter"] for item in selected}):
                continue
            result.append(mask)
        return result

    return replicas, side_masks(payload["read"]), side_masks(payload["write"])


def ids_for(mask, replicas):
    return [
        replicas[i]["id"]
        for i in range(len(replicas))
        if mask & (1 << i)
    ]


def expected_analysis(payload):
    replicas, raw_reads, raw_writes = feasible_masks_brute(payload)
    reads = sorted(raw_reads, key=lambda mask: (mask.bit_count(), mask))
    writes = sorted(raw_writes, key=lambda mask: (mask.bit_count(), mask))
    if not reads or not writes:
        return {
            "read_possible": bool(reads),
            "write_possible": bool(writes),
            "minimum_intersection": None,
            "witness_read": None,
            "witness_write": None,
            "disjoint_counterexample": None,
            "safe": False,
        }

    min_intersection = min(
        (read_mask & write_mask).bit_count()
        for read_mask in reads
        for write_mask in writes
    )
    witness_read, witness_write = next(
        (read_mask, write_mask)
        for read_mask in reads
        for write_mask in writes
        if (read_mask & write_mask).bit_count() == min_intersection
    )
    expected = {
        "read_possible": True,
        "write_possible": True,
        "minimum_intersection": min_intersection,
        "witness_read": {"replica_ids": ids_for(witness_read, replicas)},
        "witness_write": {"replica_ids": ids_for(witness_write, replicas)},
        "disjoint_counterexample": None,
        "safe": min_intersection > 0,
    }
    if min_intersection == 0:
        disjoint = [
            (read_mask, write_mask)
            for read_mask in reads
            for write_mask in writes
            if read_mask & write_mask == 0
        ]
        read_mask, write_mask = min(
            disjoint,
            key=lambda pair: (
                pair[0].bit_count() + pair[1].bit_count(),
                ids_for(pair[0], replicas),
                ids_for(pair[1], replicas),
            ),
        )
        expected["disjoint_counterexample"] = {
            "read": {"replica_ids": ids_for(read_mask, replicas)},
            "write": {"replica_ids": ids_for(write_mask, replicas)},
        }
    return expected


def restored_payload(payload, positions):
    """返回把指定下标副本标记为在线后的新 payload。"""
    restored = deepcopy(payload)
    for position in positions:
        restored["replicas"][position]["online"] = True
    return restored


def expected_recovery_plan(payload):
    """独立枚举离线副本子集，重放 expected_analysis 得到恢复规划。"""
    current = expected_analysis(payload)

    def view(evaluated):
        return {
            "read_possible": evaluated["read_possible"],
            "write_possible": evaluated["write_possible"],
            "minimum_intersection": evaluated["minimum_intersection"],
            "witness_read": evaluated["witness_read"],
            "witness_write": evaluated["witness_write"],
        }

    if current["safe"]:
        return {
            "already_safe": True,
            "reachable": True,
            "restore": [],
            **view(current),
        }

    offline = [
        index
        for index, item in enumerate(payload["replicas"])
        if not item["online"]
    ]
    for size in range(1, len(offline) + 1):
        best = None
        for combo in combinations(offline, size):
            evaluated = expected_analysis(restored_payload(payload, combo))
            if not evaluated["safe"]:
                continue
            ids = sorted(payload["replicas"][index]["id"] for index in combo)
            if best is None or ids < best[0]:
                best = (ids, evaluated)
        if best is not None:
            ids, evaluated = best
            return {
                "already_safe": False,
                "reachable": True,
                "restore": ids,
                **view(evaluated),
            }

    return {
        "already_safe": False,
        "reachable": False,
        "restore": None,
        "read_possible": None,
        "write_possible": None,
        "minimum_intersection": None,
        "witness_read": None,
        "witness_write": None,
    }


def toggled_payload(payload, replica_ids):
    """返回把给定 id 副本在线状态取反后的新 payload。"""
    result = deepcopy(payload)
    targets = set(replica_ids)
    for item in result["replicas"]:
        if item["id"] in targets:
            item["online"] = not item["online"]
    return result


def expected_maintenance_rehearsal(payload, requested_ids):
    """独立枚举全部排列，重放每一步的完整裁决。"""
    initial = expected_analysis(payload)
    if not initial["safe"]:
        return {
            "feasible": False,
            "order": None,
            "steps": None,
            "reason": "initial state is unsafe",
        }

    ids = sorted(requested_ids)
    for order in permutations(ids):
        steps = []
        for step_number, replica_id in enumerate(order, start=1):
            prefix = order[:step_number]
            evaluated = expected_analysis(toggled_payload(payload, prefix))
            if not evaluated["safe"]:
                break

            online_after = next(
                item["online"]
                for item in toggled_payload(payload, prefix)["replicas"]
                if item["id"] == replica_id
            )
            steps.append(
                {
                    "replica_id": replica_id,
                    "online_after": online_after,
                    "read_possible": evaluated["read_possible"],
                    "write_possible": evaluated["write_possible"],
                    "minimum_intersection": evaluated["minimum_intersection"],
                    "witness_read": evaluated["witness_read"],
                    "witness_write": evaluated["witness_write"],
                    "safe": evaluated["safe"],
                }
            )

        if len(steps) == len(order):
            return {"feasible": True, "order": list(order), "steps": steps}

    return {
        "feasible": False,
        "order": None,
        "steps": None,
        "reason": "no complete safe toggle order exists",
    }


def analyze_with_rehearsal(payload, requested_ids):
    return analyze({**payload, "maintenance_rehearsal": requested_ids})


def analyze_with_recovery(payload):
    return analyze({**payload, "recovery": True})


def test_weight_threshold_alone_misses_region_induced_disjoint_pair():
    payload = make_payload(
        [
            replica("a1", 6, "A"),
            replica("a2", 6, "A"),
            replica("b1", 6, "B"),
            replica("b2", 6, "B"),
        ],
        read_threshold=12,
        write_threshold=12,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    result = analyze(payload)

    assert result["read_possible"] is True
    assert result["write_possible"] is True
    assert result["minimum_intersection"] == 0
    assert result["safe"] is False
    assert result["disjoint_counterexample"] == {
        "read": {"replica_ids": ["a1", "b1"]},
        "write": {"replica_ids": ["a2", "b2"]},
    }


def test_all_pairs_intersect_when_each_side_needs_three_of_four():
    payload = make_payload(
        [
            replica("a1", 4, "A"),
            replica("a2", 4, "A"),
            replica("b1", 4, "B"),
            replica("b2", 4, "B"),
        ],
        read_threshold=12,
        write_threshold=12,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    result = analyze(payload)

    assert result == {
        "read_possible": True,
        "write_possible": True,
        "minimum_intersection": 2,
        "witness_read": {"replica_ids": ["a1", "a2", "b1"]},
        "witness_write": {"replica_ids": ["a1", "a2", "b2"]},
        "disjoint_counterexample": None,
        "safe": True,
    }


def test_offline_replicas_cannot_be_selected():
    payload = make_payload(
        [
            replica("a1", 9, "A", online=True),
            replica("b1", 9, "B", online=False),
        ],
        read_threshold=1,
        write_threshold=1,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    assert analyze(payload) == {
        "read_possible": False,
        "write_possible": False,
        "minimum_intersection": None,
        "witness_read": None,
        "witness_write": None,
        "disjoint_counterexample": None,
        "safe": False,
    }


def test_offline_weight_is_not_counted_but_side_can_still_be_possible():
    payload = make_payload(
        [
            replica("offline-heavy", 9, "A", online=False),
            replica("online-light", 1, "A", online=True),
        ],
        read_threshold=1,
        write_threshold=9,
    )

    result = analyze(payload)

    assert result["read_possible"] is True
    assert result["write_possible"] is False
    assert result["safe"] is False
    assert result["minimum_intersection"] is None


def test_equal_weight_tie_uses_read_ids_then_write_ids():
    payload = make_payload(
        [
            replica("d1", 1, "X"),
            replica("d2", 1, "X"),
            replica("d3", 1, "X"),
            replica("d4", 1, "X"),
        ],
        read_threshold=2,
        write_threshold=2,
    )

    result = analyze(payload)

    assert result["minimum_intersection"] == 0
    assert result["disjoint_counterexample"] == {
        "read": {"replica_ids": ["d1", "d2"]},
        "write": {"replica_ids": ["d3", "d4"]},
    }


def test_tie_total_size_has_priority_over_lexicographic_order():
    payload = make_payload(
        [
            replica("aa", 1, "A"),
            replica("bb", 2, "A"),
            replica("cc", 2, "A"),
        ],
        read_threshold=2,
        write_threshold=2,
    )

    result = analyze(payload)

    # 权重均为 2 的 bb 与 cc 是总成员数 2 的不相交对，优先于单权重 id
    # 字典序更小的三成员对。
    assert result["disjoint_counterexample"] == {
        "read": {"replica_ids": ["bb"]},
        "write": {"replica_ids": ["cc"]},
    }
    assert result["minimum_intersection"] == 0


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            make_payload(
                [
                    replica("a", 3, "A"),
                    replica("b", 3, "B"),
                    replica("c", 5, "A"),
                    replica("d", 5, "B", online=False),
                ],
                read_threshold=5,
                write_threshold=3,
                read_dcs=["A", "B"],
                write_dcs=["A"],
            ),
            id="offline-region-constraint",
        ),
        pytest.param(
            make_payload(
                [replica(f"r{i}", i % 3 + 1, f"DC{i % 2}") for i in range(12)],
                read_threshold=10,
                write_threshold=12,
                read_dcs=["DC0"],
                write_dcs=["DC1"],
            ),
            id="twelve-replicas-equal-pattern",
        ),
        pytest.param(
            make_payload(
                [replica("x", 9), replica("y", 9)],
                read_threshold=9,
                write_threshold=9,
            ),
            id="equal-heavy-weights",
        ),
    ],
)
def test_manual_cases_match_bitmask_oracle(payload):
    assert analyze(payload) == expected_analysis(payload)


def random_payload(seed):
    rng = __import__("random").Random(seed)
    n = rng.randint(2, 10)
    ids = [f"id-{index:02d}-{rng.randrange(36):x}" for index in range(n)]
    assert len(set(ids)) == n
    datacenters = [rng.choice(["dc-a", "dc-b", "dc-c"]) for _ in range(n)]
    replicas = [
        replica(
            identifier,
            weight=rng.randint(1, 9),
            dc=datacenter,
            online=rng.random() >= 0.2,
        )
        for identifier, datacenter in zip(ids, datacenters)
    ]

    def side():
        dc_options = sorted(set(datacenters))
        required = rng.sample(dc_options, rng.randrange(len(dc_options) + 1))
        return {
            "weight_threshold": rng.randrange(0, 30),
            "required_datacenters": required,
        }

    return {"replicas": replicas, "read": side(), "write": side()}


@pytest.mark.parametrize("seed", range(45))
def test_random_small_instances_match_bitmask_enumeration(seed):
    payload = random_payload(seed)
    assert analyze(payload) == expected_analysis(payload)


def test_recovery_plan_restores_cross_datacenter_quorum():
    payload = make_payload(
        [
            replica("a1", 6, "A"),
            replica("a2", 6, "A"),
            replica("b1", 6, "B", online=False),
        ],
        read_threshold=12,
        write_threshold=12,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    result = analyze_with_recovery(payload)

    # 当前 B 机房没有在线副本，两侧都不可行；恢复 b1 后跨机房仲裁成立。
    assert result["read_possible"] is False
    assert result["write_possible"] is False
    plan = result["recovery_plan"]
    assert plan["already_safe"] is False
    assert plan["reachable"] is True
    assert plan["restore"] == ["b1"]
    assert plan["read_possible"] is True
    assert plan["write_possible"] is True
    assert plan["minimum_intersection"] == 1
    assert plan["witness_read"] == {"replica_ids": ["a1", "b1"]}
    assert plan["witness_write"] == {"replica_ids": ["a2", "b1"]}
    assert plan == expected_recovery_plan(payload)


def test_recovery_plan_empty_quorum_side_is_never_safe():
    payload = make_payload(
        [replica("a", 3, "A"), replica("b", 3, "B", online=False)],
        read_threshold=0,
        write_threshold=3,
    )

    result = analyze_with_recovery(payload)

    # 读侧阈值为 0，空仲裁集永远可行且与任何写仲裁集不相交；
    # 两侧各自可行不等于安全，恢复任何副本都无法达到安全。
    assert result["read_possible"] is True
    assert result["write_possible"] is True
    assert result["safe"] is False
    plan = result["recovery_plan"]
    assert plan["already_safe"] is False
    assert plan["reachable"] is False
    assert plan["restore"] is None
    assert plan["minimum_intersection"] is None
    assert plan["witness_read"] is None
    assert plan["witness_write"] is None
    assert plan == expected_recovery_plan(payload)


def test_recovery_plan_tie_prefers_lexicographically_smallest_ids():
    payload = make_payload(
        [
            replica("r1", 5, "A"),
            replica("r2", 5, "A", online=False),
            replica("r3", 5, "A", online=False),
        ],
        read_threshold=10,
        write_threshold=10,
    )

    plan = analyze_with_recovery(payload)["recovery_plan"]

    # 恢复 r2 或 r3 都各自形成唯一仲裁对，并列时取 id 列表字典序最小者。
    assert plan["reachable"] is True
    assert plan["restore"] == ["r2"]
    assert plan["minimum_intersection"] == 2
    assert plan["witness_read"] == {"replica_ids": ["r1", "r2"]}
    assert plan["witness_write"] == {"replica_ids": ["r1", "r2"]}
    assert plan == expected_recovery_plan(payload)


def test_recovery_plan_does_not_assume_more_replicas_stay_safe():
    payload = make_payload(
        [
            replica("a1", 5, "A"),
            replica("a2", 5, "A", online=False),
            replica("b1", 5, "B", online=False),
        ],
        read_threshold=10,
        write_threshold=5,
        write_dcs=["B"],
    )

    plan = analyze_with_recovery(payload)["recovery_plan"]

    # 只恢复 b1 即可让读、写仲裁都经过 b1，交集为 1。
    assert plan["reachable"] is True
    assert plan["restore"] == ["b1"]
    assert plan["minimum_intersection"] == 1
    assert plan["witness_read"] == {"replica_ids": ["a1", "b1"]}
    assert plan["witness_write"] == {"replica_ids": ["b1"]}

    # 多恢复 a2 反而启用不相交对 {a1,a2} 与 {b1}：恢复更多并不必然改善交集。
    fully_restored = analyze(restored_payload(payload, [1, 2]))
    assert fully_restored["read_possible"] is True
    assert fully_restored["write_possible"] is True
    assert fully_restored["minimum_intersection"] == 0
    assert fully_restored["safe"] is False
    assert plan == expected_recovery_plan(payload)


def test_recovery_plan_already_safe_returns_empty_set():
    payload = make_payload(
        [replica("a"), replica("b"), replica("c")],
        read_threshold=2,
        write_threshold=2,
    )

    result = analyze_with_recovery(payload)
    plan = result["recovery_plan"]

    assert result["safe"] is True
    assert plan["already_safe"] is True
    assert plan["reachable"] is True
    assert plan["restore"] == []
    assert plan["minimum_intersection"] == result["minimum_intersection"] == 1
    assert plan["witness_read"] == result["witness_read"]
    assert plan["witness_write"] == result["witness_write"]
    assert plan == expected_recovery_plan(payload)


def test_recovery_plan_unreachable_when_nothing_left_to_restore():
    payload = make_payload(
        [
            replica("a1", 6, "A"),
            replica("a2", 6, "A"),
            replica("b1", 6, "B"),
            replica("b2", 6, "B"),
        ],
        read_threshold=12,
        write_threshold=12,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    result = analyze_with_recovery(payload)
    plan = result["recovery_plan"]

    assert result["minimum_intersection"] == 0
    assert plan["already_safe"] is False
    assert plan["reachable"] is False
    assert plan["restore"] is None
    assert plan == expected_recovery_plan(payload)


def random_planning_payload(seed):
    rng = __import__("random").Random(seed)
    n = rng.randint(2, 7)
    ids = [f"p{index:02d}-{rng.randrange(36):x}" for index in range(n)]
    assert len(set(ids)) == n
    datacenters = [rng.choice(["dc-a", "dc-b"]) for _ in range(n)]
    replicas = [
        replica(
            identifier,
            weight=rng.randint(1, 9),
            dc=datacenter,
            online=rng.random() >= 0.35,
        )
        for identifier, datacenter in zip(ids, datacenters)
    ]

    def side():
        dc_options = sorted(set(datacenters))
        required = rng.sample(dc_options, rng.randrange(len(dc_options) + 1))
        return {
            "weight_threshold": rng.randrange(0, 25),
            "required_datacenters": required,
        }

    return {"replicas": replicas, "read": side(), "write": side()}


@pytest.mark.parametrize("seed", range(20))
def test_random_recovery_plans_match_subset_enumeration(seed):
    payload = random_planning_payload(seed)
    result = analyze_with_recovery(payload)
    assert result == {
        **expected_analysis(payload),
        "recovery_plan": expected_recovery_plan(payload),
    }


def test_maintenance_rehearsal_empty_sequence_reports_initial_judgement():
    payload = make_payload(
        [replica("a", 2), replica("b", 2)],
        read_threshold=4,
        write_threshold=4,
    )

    result = analyze_with_rehearsal(payload, [])["maintenance_rehearsal_plan"]

    assert result == {
        "feasible": True,
        "order": [],
        "steps": [],
    }


def test_maintenance_rehearsal_returns_lexicographically_smallest_safe_order():
    payload = make_payload(
        [
            replica("a", 2, "A", online=True),
            replica("b", 2, "A", online=True),
            replica("c", 2, "A", online=True),
            replica("x", 2, "A", online=False),
            replica("y", 2, "A", online=False),
        ],
        read_threshold=4,
        write_threshold=4,
    )

    result = analyze_with_rehearsal(payload, ["a", "b", "c", "x", "y"])

    assert result["maintenance_rehearsal_plan"] == expected_maintenance_rehearsal(
        payload, ["a", "b", "c", "x", "y"]
    )
    plan = result["maintenance_rehearsal_plan"]
    assert plan["feasible"] is True
    # 字典序最小排列以 a 开头；必须在只有两台在线时恢复 x，再下线 b，
    # 避免三台在线时出现权重为 4 的不相交仲裁对。
    assert plan["order"] == ["a", "x", "b", "y", "c"]
    assert [step["replica_id"] for step in plan["steps"]] == plan["order"]
    assert [step["online_after"] for step in plan["steps"]] == [
        False,
        True,
        False,
        True,
        False,
    ]
    assert [step["minimum_intersection"] for step in plan["steps"]] == [
        2,
        1,
        2,
        1,
        2,
    ]

    # 另一排列在前两步仍安全，第三步恢复 y 后出现不相交仲裁；
    # 虽然完成全部五次切换后的终态安全，该中间前缀必须被拒绝。
    midpoint_failure = analyze(toggled_payload(payload, ["a", "x", "y"]))
    assert midpoint_failure["safe"] is False
    assert midpoint_failure["minimum_intersection"] == 0
    assert analyze(toggled_payload(payload, plan["order"]))["safe"] is True


def test_maintenance_rehearsal_cross_datacenter_keeps_every_prefix_covered():
    payload = make_payload(
        [
            replica("a1", 2, "A", online=True),
            replica("a3", 2, "A", online=False),
            replica("b1", 2, "B", online=True),
            replica("b3", 2, "B", online=False),
        ],
        read_threshold=4,
        write_threshold=4,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    plan = analyze_with_rehearsal(payload, ["a1", "a3", "b1", "b3"])[
        "maintenance_rehearsal_plan"
    ]

    assert plan == expected_maintenance_rehearsal(
        payload, ["a1", "a3", "b1", "b3"]
    )
    assert plan["feasible"] is True
    # 先下线任一唯一在线机房副本都会失去该机房；必须先恢复同机房替代者。
    assert plan["order"] == ["a3", "a1", "b3", "b1"]
    assert plan["steps"][0]["witness_read"] == {"replica_ids": ["a1", "b1"]}
    assert plan["steps"][0]["witness_write"] == {"replica_ids": ["a3", "b1"]}
    assert plan["steps"][-1]["witness_read"] == {"replica_ids": ["a3", "b3"]}


def test_maintenance_rehearsal_failure_omits_partial_plan():
    payload = make_payload(
        [
            replica("a", 1, "A"),
            replica("b", 4, "A"),
            replica("c", 4, "A"),
            replica("x", 8, "A", online=False),
        ],
        read_threshold=8,
        write_threshold=9,
    )
    requested = ["a", "x"]

    plan = analyze_with_rehearsal(payload, requested)[
        "maintenance_rehearsal_plan"
    ]

    assert plan == {
        "feasible": False,
        "order": None,
        "steps": None,
        "reason": "no complete safe toggle order exists",
    }
    assert plan == expected_maintenance_rehearsal(payload, requested)

    # 先下线 a 会让写侧失去唯一三台仲裁；先恢复 x 会启用不相交的
    # {b,c} 与 {a,x}。全部切换后的最终状态却安全，说明不能只看终态。
    assert analyze(toggled_payload(payload, ["a"]))["write_possible"] is False
    assert analyze(toggled_payload(payload, ["x"]))["safe"] is False
    final_state = analyze(toggled_payload(payload, requested))
    assert final_state["safe"] is True
    assert final_state["minimum_intersection"] == 1


def test_maintenance_rehearsal_unsafe_initial_state_has_no_executable_steps():
    payload = make_payload(
        [
            replica("a1", 6, "A"),
            replica("a2", 6, "A"),
            replica("b1", 6, "B"),
            replica("b2", 6, "B"),
        ],
        read_threshold=12,
        write_threshold=12,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    plan = analyze_with_rehearsal(payload, ["a1", "b2"])[
        "maintenance_rehearsal_plan"
    ]

    assert plan == {
        "feasible": False,
        "order": None,
        "steps": None,
        "reason": "initial state is unsafe",
    }
    assert plan == expected_maintenance_rehearsal(payload, ["a1", "b2"])


@pytest.mark.parametrize("seed", range(25))
def test_random_maintenance_rehearsals_match_permutation_enumeration(seed):
    payload = random_planning_payload(seed)
    rng = __import__("random").Random(900 + seed)
    all_ids = [item["id"] for item in payload["replicas"]]
    count = rng.randint(0, min(5, len(all_ids)))
    requested = rng.sample(all_ids, count)

    result = analyze_with_rehearsal(payload, requested)

    assert result == {
        **expected_analysis(payload),
        "maintenance_rehearsal_plan": expected_maintenance_rehearsal(
            payload, requested
        ),
    }


@pytest.mark.parametrize(
    "requested,message",
    [
        ("a", "must be a list of strings"),
        (["a"], "unknown replica id"),
        (["a", "a"], "must be unique"),
        (["a", "b", "c", "d", "e", "f"], "at most 5"),
        ([""], "non-empty ASCII"),
    ],
)
def test_maintenance_rehearsal_validates_requested_replicas(requested, message):
    payload = make_payload(
        [replica(identifier) for identifier in ["a", "b", "c", "d", "e"]]
    )
    with pytest.raises(ValidationError, match=message):
        analyze({**payload, "maintenance_rehearsal": requested})


def test_maintenance_rehearsal_accepts_exactly_five_distinct_replicas():
    payload = make_payload(
        [replica(identifier, 2) for identifier in ["a", "b", "c", "x", "y"]],
        read_threshold=4,
        write_threshold=4,
    )
    result = analyze(
        {**payload, "maintenance_rehearsal": ["a", "b", "c", "x", "y"]}
    )

    assert result["maintenance_rehearsal_plan"] == expected_maintenance_rehearsal(
        payload, ["a", "b", "c", "x", "y"]
    )


def test_maintenance_rehearsal_can_coexist_with_recovery_planning():
    payload = make_payload(
        [
            replica("a", 2, "A"),
            replica("b", 2, "A"),
            replica("c", 2, "A"),
            replica("x", 2, "A", online=False),
            replica("y", 2, "A", online=False),
        ],
        read_threshold=4,
        write_threshold=4,
    )

    result = analyze(
        {**payload, "recovery": True, "maintenance_rehearsal": ["a", "x"]}
    )

    assert result["recovery_plan"] == expected_recovery_plan(payload)
    assert result["maintenance_rehearsal_plan"] == expected_maintenance_rehearsal(
        payload, ["a", "x"]
    )


def test_recovery_disabled_keeps_response_unchanged():
    payload = make_payload(
        [replica("a", 9), replica("b", 9)],
        read_threshold=9,
        write_threshold=9,
    )

    assert analyze(payload) == expected_analysis(payload)
    assert "recovery_plan" not in analyze(payload)
    assert analyze({**payload, "recovery": False}) == expected_analysis(payload)


@pytest.mark.parametrize("recovery", ["yes", 1, 0, {}, [], {"enabled": True}])
def test_recovery_flag_must_be_boolean(recovery):
    payload = make_payload([replica("a"), replica("b")])
    payload["recovery"] = recovery
    with pytest.raises(ValidationError, match="recovery must be a boolean"):
        analyze(payload)


def test_invalid_input_with_recovery_raises_before_planning():
    payload = {"replicas": [], "recovery": True}
    with pytest.raises(ValidationError, match="between 2 and 12"):
        analyze(payload)


@pytest.mark.parametrize(
    "bad_payload,message",
    [
        ({"replicas": []}, "between 2 and 12"),
        (
            make_payload([replica("same"), replica("same")]),
            "duplicate replica id",
        ),
        (
            make_payload([replica("a", 10), replica("b")]),
            "between 1 and 9",
        ),
        (
            make_payload(
                [replica("a"), replica("b")],
                read_dcs=["missing"],
            ),
            "read",
        ),
    ],
)
def test_invalid_input_raises_validation_error(bad_payload, message):
    with pytest.raises(ValidationError, match=message):
        analyze(bad_payload)


def test_cli_reads_stdin_and_writes_json():
    payload = make_payload(
        [replica("a", 9), replica("b", 9)],
        read_threshold=9,
        write_threshold=9,
    )
    completed = subprocess.run(
        [sys.executable, "-m", "quorum"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == expected_analysis(payload)


def test_http_service_accepts_json_and_reports_validation_errors():
    server = build_server("127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = make_payload(
            [replica("a", 9), replica("b", 9)],
            read_threshold=9,
            write_threshold=9,
        )
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert json.loads(response.read()) == expected_analysis(payload)

        bad_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=b"{not-json}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_request, timeout=5)
        assert exc_info.value.code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def recovery_payload():
    return make_payload(
        [
            replica("a1", 6, "A"),
            replica("a2", 6, "A"),
            replica("b1", 6, "B", online=False),
        ],
        read_threshold=12,
        write_threshold=12,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )


def test_cli_recovery_planning_enabled_via_payload():
    payload = {**recovery_payload(), "recovery": True}
    completed = subprocess.run(
        [sys.executable, "-m", "quorum"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        **expected_analysis(payload),
        "recovery_plan": expected_recovery_plan(payload),
    }


def maintenance_payload():
    return make_payload(
        [
            replica("a", 2, "A"),
            replica("b", 2, "A"),
            replica("c", 2, "A"),
            replica("x", 2, "A", online=False),
            replica("y", 2, "A", online=False),
        ],
        read_threshold=4,
        write_threshold=4,
    )


def test_cli_maintenance_rehearsal_enabled_via_payload():
    requested = ["a", "x", "b", "y", "c"]
    payload = {**maintenance_payload(), "maintenance_rehearsal": requested}
    completed = subprocess.run(
        [sys.executable, "-m", "quorum"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        **expected_analysis(payload),
        "maintenance_rehearsal_plan": expected_maintenance_rehearsal(
            maintenance_payload(), requested
        ),
    }


def test_cli_invalid_maintenance_rehearsal_exits_with_error():
    payload = {**maintenance_payload(), "maintenance_rehearsal": ["unknown"]}
    completed = subprocess.run(
        [sys.executable, "-m", "quorum"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 2
    assert "unknown replica id" in completed.stderr
    assert completed.stdout == ""


def test_cli_invalid_recovery_flag_exits_with_error():
    payload = {**recovery_payload(), "recovery": "yes"}
    completed = subprocess.run(
        [sys.executable, "-m", "quorum"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 2
    assert "recovery must be a boolean" in completed.stderr
    assert completed.stdout == ""


def test_http_recovery_planning_enabled_via_payload():
    server = build_server("127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = {**recovery_payload(), "recovery": True}
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert json.loads(response.read()) == {
                **expected_analysis(payload),
                "recovery_plan": expected_recovery_plan(payload),
            }

        # 未启用规划时响应保持原样，不含 recovery_plan。
        plain_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps(recovery_payload()).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(plain_request, timeout=5) as response:
            assert response.status == 200
            assert json.loads(response.read()) == expected_analysis(
                recovery_payload()
            )

        bad_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps({**recovery_payload(), "recovery": 1}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_request, timeout=5)
        assert exc_info.value.code == 400
        assert b"recovery must be a boolean" in exc_info.value.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_maintenance_rehearsal_enabled_via_payload():
    server = build_server("127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        requested = ["a", "x", "b", "y", "c"]
        payload = {**maintenance_payload(), "maintenance_rehearsal": requested}
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert json.loads(response.read()) == {
                **expected_analysis(payload),
                "maintenance_rehearsal_plan": expected_maintenance_rehearsal(
                    maintenance_payload(), requested
                ),
            }

        plain_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps(maintenance_payload()).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(plain_request, timeout=5) as response:
            assert response.status == 200
            response_payload = json.loads(response.read())
            assert response_payload == expected_analysis(maintenance_payload())
            assert "maintenance_rehearsal_plan" not in response_payload

        bad_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps(
                {**maintenance_payload(), "maintenance_rehearsal": ["a"] * 2}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_request, timeout=5)
        assert exc_info.value.code == 400
        assert b"must be unique" in exc_info.value.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
