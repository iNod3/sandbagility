import pkgutil
import inspect

AvailableMonitors = []

for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
    module = loader.find_module(module_name).load_module(module_name)
    for name, object in inspect.getmembers(module, inspect.isclass):
        if not hasattr(object, '_NAME'): continue
        if object._NAME is None: continue
        globals()[name] = object
        AvailableMonitors.append(object)
