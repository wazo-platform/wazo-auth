from __future__ import annotations

import logging
from functools import partial
from typing import Any

from stevedore.named import NamedExtensionManager
from xivo.plugin_helpers import load_plugin, on_load_failure, on_missing_entrypoints

logger = logging.getLogger(__name__)


def load_ordered(
    namespace: str, enabled: list[str], load_args: Any
) -> NamedExtensionManager | None:
    logger.debug('Enabled plugins for namespace "%s": %s', namespace, enabled)
    if not enabled:
        logger.info('no enabled plugins for namespace "%s"', namespace)
        return None

    manager = NamedExtensionManager(
        namespace,
        enabled,
        name_order=True,
        on_load_failure_callback=on_load_failure,
        on_missing_entrypoints_callback=partial(on_missing_entrypoints, namespace),
        invoke_on_load=True,
    )

    manager.map(load_plugin, *load_args)

    return manager
