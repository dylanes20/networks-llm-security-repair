"""Compatibility entry point for finalizing an already frozen attempt."""
import sys

from run_experiment import main


if __name__ == "__main__":
    sys.argv.append("--resume")
    main()
