"""枚举在线副本的读、写仲裁集并检查交集安全性。

副本数最多为 12，因此直接枚举 4096 个集合掩码。权重门槛与机房覆盖是
两个不同维度：仅凭读、写权重阈值之和不能推断两侧仲裁集必相交。

输入带 ``"recovery": true`` 时追加恢复规划：只把当前离线副本作为候选，
枚举恢复子集并逐一重新裁决，找出恢复数量最少且恢复后读写仲裁仍两两
相交的集合。

输入带 ``"maintenance_rehearsal"`` 时预演维护顺序：每个指定副本恰好
切换一次在线状态，并要求初态及每一步切换后都保持读写可行且所有可行
读写仲裁相交。
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from itertools import combinations, permutations
from typing import Any, Mapping


class ValidationError(ValueError):
    """输入 JSON 不符合协议。"""


@dataclass(frozen=True)
class _Side:
    threshold: int
    required_datacenters: tuple[str, ...]


@dataclass(frozen=True)
class _Replica:
    replica_id: str
    weight: int
    datacenter: str
    online: bool


def _is_non_empty_ascii(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0 and value.isascii()


def _as_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < 0:
        raise ValidationError(f"{field} must be non-negative")
    return value


def _as_str_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValidationError(f"{field} must be a list of strings")
    items = list(value)
    if any(not item or not item.isascii() for item in items):
        raise ValidationError(f"{field} must contain non-empty ASCII strings")
    return items


def _side(spec: Any, name: str) -> _Side:
    if not isinstance(spec, Mapping):
        raise ValidationError(f"{name} must be an object")

    required = _as_str_list(
        spec.get("required_datacenters", []),
        f"{name}.required_datacenters",
    )
    if len(required) != len(set(required)):
        raise ValidationError(f"{name}.required_datacenters must be unique")

    return _Side(
        threshold=_as_int(spec.get("weight_threshold", 0), f"{name}.weight_threshold"),
        required_datacenters=tuple(required),
    )


def _parse_replicas(value: Any) -> list[_Replica]:
    if not isinstance(value, list):
        raise ValidationError("replicas must be a list")
    if not 2 <= len(value) <= 12:
        raise ValidationError("replicas must contain between 2 and 12 entries")

    replicas: list[_Replica] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        field = f"replicas[{index}]"
        if not isinstance(item, Mapping):
            raise ValidationError(f"{field} must be an object")

        replica_id = item.get("id")
        if not _is_non_empty_ascii(replica_id):
            raise ValidationError(f"{field}.id must be a non-empty ASCII string")
        assert isinstance(replica_id, str)
        if replica_id in seen:
            raise ValidationError(f"duplicate replica id: {replica_id}")
        seen.add(replica_id)

        weight = item.get("weight")
        if isinstance(weight, bool) or not isinstance(weight, int):
            raise ValidationError(f"{field}.weight must be an integer between 1 and 9")
        if not 1 <= weight <= 9:
            raise ValidationError(f"{field}.weight must be an integer between 1 and 9")

        datacenter = item.get("datacenter")
        if not _is_non_empty_ascii(datacenter):
            raise ValidationError(
                f"{field}.datacenter must be a non-empty ASCII string"
            )
        assert isinstance(datacenter, str)

        online = item.get("online")
        if not isinstance(online, bool):
            raise ValidationError(f"{field}.online must be a boolean")

        replicas.append(
            _Replica(
                replica_id=replica_id,
                weight=weight,
                datacenter=datacenter,
                online=online,
            )
        )

    # 所有裁决均使用固定 id 字典序，避免输入顺序影响并列反例。
    replicas.sort(key=lambda replica: replica.replica_id)
    return replicas


def _required_masks(replicas: list[_Replica]) -> dict[str, int]:
    masks: dict[str, int] = {}
    for index, replica in enumerate(replicas):
        masks.setdefault(replica.datacenter, 0)
        masks[replica.datacenter] |= 1 << index
    return masks


def _feasible_masks(
    replicas: list[_Replica],
    side: _Side,
    datacenter_masks: Mapping[str, int],
) -> list[int]:
    """返回按 (成员数, id 列表字典序) 排序的可行仲裁集。"""
    required_masks: list[int] = []
    for datacenter in side.required_datacenters:
        if datacenter not in datacenter_masks:
            return []
        required_masks.append(datacenter_masks[datacenter])

    n = len(replicas)
    mask_weights = [0] * (1 << n)
    online_mask = 0
    for index, replica in enumerate(replicas):
        bit = 1 << index
        for mask in range(bit):
            mask_weights[bit | mask] = mask_weights[mask] + replica.weight
        if replica.online:
            online_mask |= bit

    result: list[int] = []

    for mask in range(1 << n):
        if mask & ~online_mask:
            continue
        if mask_weights[mask] < side.threshold:
            continue
        if any(not (mask & required) for required in required_masks):
            continue
        result.append(mask)

    # 对相同成员数的掩码，数值递增等于排序后的 id 列表字典序递增。
    result.sort(key=lambda mask: (mask.bit_count(), mask))
    return result


def _mask_to_ids(mask: int, replica_ids: list[str]) -> list[str]:
    return [
        replica_ids[index]
        for index in range(len(replica_ids))
        if mask & (1 << index)
    ]


def _witness(mask: int, replica_ids: list[str]) -> dict[str, list[str]]:
    return {"replica_ids": _mask_to_ids(mask, replica_ids)}


def _check_required_datacenters(
    replicas: list[_Replica],
    read: _Side,
    write: _Side,
) -> None:
    known = {replica.datacenter for replica in replicas}
    for name, side in (("read", read), ("write", write)):
        for datacenter in side.required_datacenters:
            if datacenter not in known:
                raise ValidationError(
                    f"{name}.required_datacenters references unknown datacenter: "
                    f"{datacenter}"
                )


def _parse_recovery(value: Any) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValidationError("recovery must be a boolean")
    return value


def _parse_maintenance_rehearsal(
    value: Any,
    replicas: list[_Replica],
) -> tuple[int, ...] | None:
    """解析维护预演请求，并转换为按副本 id 排序的下标序列。

    协议使用 ``{"maintenance_rehearsal": {"replica_ids": [...]}}``；直接
    传 id 列表也接受，方便 CLI 手工调用。预演顺序按 id 序列比较字典序，
    这里先检查互异并排序，后续生成排列时即可按固定 id 字典序枚举。
    """
    if value is None:
        return None
    if isinstance(value, Mapping):
        value = value.get("replica_ids")
        if value is None:
            raise ValidationError("maintenance_rehearsal.replica_ids is required")
    if not isinstance(value, list):
        raise ValidationError("maintenance_rehearsal must be a list")
    if len(value) > 5:
        raise ValidationError("maintenance_rehearsal can contain at most 5 replica ids")

    ids = _as_str_list(value, "maintenance_rehearsal.replica_ids")
    if len(ids) != len(set(ids)):
        raise ValidationError("maintenance_rehearsal replica ids must be unique")

    index_by_id = {replica.replica_id: index for index, replica in enumerate(replicas)}
    indices: list[int] = []
    for replica_id in ids:
        if replica_id not in index_by_id:
            raise ValidationError(
                f"maintenance_rehearsal references unknown replica id: {replica_id}"
            )
        indices.append(index_by_id[replica_id])

    # 返回排序后的下标集合；_plan_maintenance_rehearsal 枚举其全部排列。
    return tuple(sorted(indices))


def _evaluate(
    replicas: list[_Replica],
    read: _Side,
    write: _Side,
    datacenter_masks: Mapping[str, int],
) -> dict[str, Any]:
    """对一种副本在线状态枚举仲裁集并裁决交集安全性。"""
    replica_ids = [replica.replica_id for replica in replicas]

    read_masks = _feasible_masks(replicas, read, datacenter_masks)
    write_masks = _feasible_masks(replicas, write, datacenter_masks)
    read_possible = bool(read_masks)
    write_possible = bool(write_masks)

    result: dict[str, Any] = {
        "read_possible": read_possible,
        "write_possible": write_possible,
        "minimum_intersection": None,
        "witness_read": None,
        "witness_write": None,
        "disjoint_counterexample": None,
        "safe": False,
    }

    if not read_possible or not write_possible:
        return result

    best_intersection: int | None = None
    best_read = 0
    best_write = 0

    for read_mask in read_masks:
        for write_mask in write_masks:
            intersection = (read_mask & write_mask).bit_count()
            if best_intersection is None or intersection < best_intersection:
                best_intersection = intersection
                best_read = read_mask
                best_write = write_mask
                if best_intersection == 0:
                    break
        if best_intersection == 0:
            break

    assert best_intersection is not None
    result["minimum_intersection"] = best_intersection
    result["witness_read"] = _witness(best_read, replica_ids)
    result["witness_write"] = _witness(best_write, replica_ids)

    if best_intersection > 0:
        result["safe"] = True
        return result

    # 仅在确实存在不相交读写对时选择反例。排序顺序保证成员数优先；
    # 成员总数相同的候选再比较读、写两侧排序后的 id 列表。
    disjoint_read: int | None = None
    disjoint_write: int | None = None
    best_total = len(replicas) * 2 + 1
    best_key: tuple[list[str], list[str]] | None = None

    for read_mask in read_masks:
        read_size = read_mask.bit_count()
        if read_size > best_total:
            break
        for write_mask in write_masks:
            write_size = write_mask.bit_count()
            total_size = read_size + write_size
            if total_size > best_total:
                break
            if read_mask & write_mask:
                continue

            candidate_key = (
                _mask_to_ids(read_mask, replica_ids),
                _mask_to_ids(write_mask, replica_ids),
            )
            if disjoint_read is None or total_size < best_total or (
                total_size == best_total
                and (best_key is None or candidate_key < best_key)
            ):
                disjoint_read = read_mask
                disjoint_write = write_mask
                best_total = total_size
                best_key = candidate_key

    assert disjoint_read is not None
    assert disjoint_write is not None
    result["disjoint_counterexample"] = {
        "read": _witness(disjoint_read, replica_ids),
        "write": _witness(disjoint_write, replica_ids),
    }

    return result


def _restore_replicas(
    replicas: list[_Replica],
    restored: set[int],
) -> list[_Replica]:
    """把指定下标的副本标记为在线，权重、机房等属性保持不变。"""
    return [
        _Replica(
            replica_id=replica.replica_id,
            weight=replica.weight,
            datacenter=replica.datacenter,
            online=replica.online or index in restored,
        )
        for index, replica in enumerate(replicas)
    ]


def _recovery_view(evaluated: Mapping[str, Any]) -> dict[str, Any]:
    """从一次裁决结果中截取恢复规划需要报告的字段。"""
    return {
        "read_possible": evaluated["read_possible"],
        "write_possible": evaluated["write_possible"],
        "minimum_intersection": evaluated["minimum_intersection"],
        "witness_read": evaluated["witness_read"],
        "witness_write": evaluated["witness_write"],
    }


def _plan_recovery(
    replicas: list[_Replica],
    read: _Side,
    write: _Side,
    datacenter_masks: Mapping[str, int],
    current: Mapping[str, Any],
) -> dict[str, Any]:
    """枚举离线副本的恢复子集，找出恢复数量最少的安全集合。

    安全指恢复后读、写两侧均可行且最小交集大于 0；仅两侧各自可行不算
    安全。交集安全性关于恢复集合不是单调的：多恢复副本可能启用新的
    不相交仲裁对，因此每个候选集合都按原权重、机房和在线语义独立重新
    裁决，按集合大小递增枚举，并列时取副本 id 列表字典序最小者。
    """
    if current["safe"]:
        return {
            "already_safe": True,
            "reachable": True,
            "restore": [],
            **_recovery_view(current),
        }

    offline_indices = [
        index for index, replica in enumerate(replicas) if not replica.online
    ]

    for size in range(1, len(offline_indices) + 1):
        best_ids: list[str] | None = None
        best_evaluated: dict[str, Any] | None = None
        for combo in combinations(offline_indices, size):
            evaluated = _evaluate(
                _restore_replicas(replicas, set(combo)),
                read,
                write,
                datacenter_masks,
            )
            if not evaluated["safe"]:
                continue
            # 副本已按 id 排序，组合内下标递增即 id 列表字典序。
            ids = [replicas[index].replica_id for index in combo]
            if best_ids is None or ids < best_ids:
                best_ids = ids
                best_evaluated = evaluated
        if best_ids is not None and best_evaluated is not None:
            return {
                "already_safe": False,
                "reachable": True,
                "restore": best_ids,
                **_recovery_view(best_evaluated),
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


def _maintenance_view(evaluated: Mapping[str, Any]) -> dict[str, Any]:
    """从一次切换后的裁决结果中截取预演需要复核的字段。"""
    return {
        "read_possible": evaluated["read_possible"],
        "write_possible": evaluated["write_possible"],
        "minimum_intersection": evaluated["minimum_intersection"],
        "witness_read": evaluated["witness_read"],
        "witness_write": evaluated["witness_write"],
    }


def _failure(reason: str) -> dict[str, Any]:
    return {
        "possible": False,
        "failure_reason": reason,
        "order": None,
        "steps": None,
    }


def _plan_maintenance_rehearsal(
    replicas: list[_Replica],
    read: _Side,
    write: _Side,
    datacenter_masks: Mapping[str, int],
    selected: tuple[int, ...],
    initial: Mapping[str, Any],
) -> dict[str, Any]:
    """枚举所选副本的全部切换排列，返回字典序最小的全程安全顺序。

    每一步都可能让离线副本上线；上线后会产生新的可选仲裁集，安全性对在
    线副本集合不单调。因此这里不能只检查初态和终态，必须对每个排列的每
    个前缀重新完整枚举读、写仲裁。任一中间状态失去可行性或出现不相交对，
    该排列立即废弃，且不返回其中尚可执行的前缀。
    """
    if not initial["safe"]:
        return _failure("initial_state_unsafe")

    # permutations 按元组字典序生成；selected 已按 id 排序，所以第一个
    # 全程安全排列就是副本 id 序列字典序最小者。
    for order in permutations(selected):
        state = replicas
        steps: list[dict[str, Any]] = []
        for step_number, index in enumerate(order, start=1):
            replica = state[index]
            replica_id = replica.replica_id
            state = [
                replace(item, online=not item.online)
                if item_index == index
                else item
                for item_index, item in enumerate(state)
            ]
            evaluated = _evaluate(state, read, write, datacenter_masks)
            if not evaluated["safe"]:
                break
            steps.append(
                {
                    "step": step_number,
                    "replica_id": replica_id,
                    "safe": True,
                    **_maintenance_view(evaluated),
                }
            )
        else:
            return {
                "possible": True,
                "failure_reason": None,
                "order": [replicas[index].replica_id for index in order],
                "steps": steps,
            }

    return _failure("no_safe_complete_order")


def analyze(payload: Mapping[str, Any]) -> dict[str, Any]:
    """分析输入并返回稳定的 JSON 兼容结果。"""
    if not isinstance(payload, Mapping):
        raise ValidationError("request body must be a JSON object")

    replicas = _parse_replicas(payload.get("replicas"))
    read = _side(payload.get("read", {}), "read")
    write = _side(payload.get("write", {}), "write")
    _check_required_datacenters(replicas, read, write)
    recovery = _parse_recovery(payload.get("recovery"))
    maintenance_rehearsal = _parse_maintenance_rehearsal(
        payload.get("maintenance_rehearsal"), replicas
    )

    datacenter_masks = _required_masks(replicas)
    result = _evaluate(replicas, read, write, datacenter_masks)
    if recovery:
        result["recovery_plan"] = _plan_recovery(
            replicas, read, write, datacenter_masks, result
        )
    if maintenance_rehearsal is not None:
        result["maintenance_rehearsal"] = _plan_maintenance_rehearsal(
            replicas,
            read,
            write,
            datacenter_masks,
            maintenance_rehearsal,
            result,
        )
    return result
