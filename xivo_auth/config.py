import yaml

def load_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f)

    return config
