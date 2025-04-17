#!/bin/bash
echo "==================================================="
echo "       UniFortress - Available Disks List          "
echo "==================================================="
echo
echo "WARNING! This script may require sudo privileges."
echo
echo "This will display a list of available disks for encryption."
echo
read -p "Press Enter to continue..." 

echo
echo "Running command:"
echo "---------------------------------------------------"

# Check if we're on macOS or Linux
if [[ "$(uname)" == "Darwin" ]]; then
  # macOS
  if [ "$EUID" -ne 0 ]; then
    echo "Escalating privileges to list devices..."
    sudo ./target/release/unifortress list-devices
  else
    ./target/release/unifortress list-devices
  fi
else
  # Linux or other Unix
  if [ "$EUID" -ne 0 ]; then
    echo "Escalating privileges to list devices..."
    sudo ./target/release/unifortress list-devices
  else
    ./target/release/unifortress list-devices
  fi
fi

echo "---------------------------------------------------"
echo
echo "Command executed. See results above."
read -p "Press Enter to exit..." 