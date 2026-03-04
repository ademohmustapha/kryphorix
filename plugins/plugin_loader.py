"""
plugins/plugin_loader.py  —  Dynamic plugin loader for Kryphorix v2.
Place plugins in /plugins/ as plugin_<name>.py with a scan(target) function.
"""
import importlib.util
import logging
from pathlib import Path

logger = logging.getLogger("kryphorix")


def load_plugins(plugin_dir: str = None) -> list:
    """Return list of scan functions from all valid plugin files.

    Security controls:
    - Only loads files matching plugin_*.py pattern
    - Validates files reside inside the designated plugin directory (no traversal)
    - Logs every load attempt for audit trail
    """
    plugin_dir = Path(plugin_dir).resolve() if plugin_dir else Path(__file__).parent.resolve()
    plugins    = []
    if not plugin_dir.is_dir():
        logger.warning(f"[Plugins] Plugin directory does not exist: {plugin_dir}")
        return plugins
    for py_file in sorted(plugin_dir.glob("plugin_*.py")):
        # Resolve to prevent symlink traversal outside the plugin directory
        try:
            resolved = py_file.resolve()
        except Exception:
            logger.warning(f"[Plugins] Cannot resolve path: {py_file}")
            continue
        if not str(resolved).startswith(str(plugin_dir)):
            logger.warning(f"[Plugins] Rejected (path traversal): {py_file.name}")
            continue
        try:
            spec = importlib.util.spec_from_file_location(py_file.stem, resolved)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "scan") and callable(mod.scan):
                plugins.append(mod.scan)
                logger.info(f"[Plugins] Loaded: {py_file.name}")
            else:
                logger.warning(f"[Plugins] No scan() function in: {py_file.name}")
        except Exception as e:
            logger.warning(f"[Plugins] Failed to load {py_file.name}: {e}")
    return plugins
