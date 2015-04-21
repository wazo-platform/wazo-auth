from stevedore.dispatch import NameDispatchExtensionManager

def load_plugins(application):
    plugins = NameDispatchExtensionManager(namespace='xivo_auth.plugins',
                                           check_func=check_plugin,
                                           on_load_failure_callback=plugins_load_fail,
                                           verify_requirements=True,
                                           propagate_map_exceptions=True,
                                           invoke_on_load=True
                                          )

    plugs = application.config['plugins']
    plugins.map(plugs, launch_plugin, application)

def check_plugin(plugin):
    return True

def launch_plugin(ext, args):
    print "Loading dynamic plugin : %s" % ext.name
    ext.obj.load(args)

def plugins_load_fail(manager, entrypoint, exception):
    print "There is an error with this module: ", manager
    print "The entry point is: ", entrypoint
    print "The exception is: ", exception
