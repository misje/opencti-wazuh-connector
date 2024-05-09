import argparse
import json
import sys
import time
import yaml
from wazuh import WazuhConnector, Config

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(
            description="OpenCTI–Wazuh enrichment connector",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("--config", "-c", help="Load configuration from file")
        parser.add_argument(
            "--format",
            "-f",
            choices=("json", "yaml"),
            default="yaml",
            help="Configuration file format",
        )
        parser.add_argument(
            "--ignore",
            "-i",
            action="store_true",
            help="Continue if configuration file cannot be opened (if the configuration is invalid, the program will still fail)",
        )
        args = parser.parse_args()
        config = None
        if args.config:
            try:
                match args.format:
                    case "json":
                        with open(args.config, "r", encoding="utf-8") as data:
                            config = Config(**json.load(data))
                    case "yaml":
                        with open(args.config, "r", encoding="utf-8") as data:
                            config = Config(**yaml.safe_load(data))
                    case _:
                        raise ValueError(
                            f"Config format {args.format} is not supported"
                        )
            except OSError as e:
                if args.ignore:
                    print(f"Failed to load config file {args.config}, ignoring")
                    config = Config.from_env()
                else:
                    raise ValueError(f"Failed to open config file {args.config}") from e
        else:
            config = Config.from_env()

        wazuh = WazuhConnector(config=config)
        wazuh.start()
    except Exception as e:
        print(e)
        time.sleep(2)
        sys.exit(0)
