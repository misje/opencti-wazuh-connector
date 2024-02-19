import sys
import time
from wazuh import WazuhConnector

if __name__ == "__main__":
    try:
        wazuh = WazuhConnector()
        wazuh.start()
    except Exception as e:
        print(e)
        time.sleep(2)
        sys.exit(0)
