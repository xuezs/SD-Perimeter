#!/bin/bash

# Set where we're working from
## These will be installation specific
DB_CONFIG=/opt/sdp/scripts/config.sh
. $DB_CONFIG

function optionsMenu {
  echo
  echo "**************************"
  echo "* SDP MANAGEMENT OPTIONS *"
  echo "**************************"
  # Prompt for an option
  PS3='Choose an Option to Continue: '
  options=("Manage Users" "Manage Groups" "Manage Gateways" "Manage Resources"
          "Exit")
    select opt in "${options[@]}"
    do
      case $opt in
        "Manage Users")
           bash $SCRIPTS_DIR/manage_clients.sh
           break
           ;;
         "Manage Groups")
           bash $SCRIPTS_DIR/manage_usergroups.sh
           break
           ;;
         "Manage Gateways")
           optionsMenu
           break
           ;;
         "Manage Resources")
           optionsMenu
           break
           ;;
         "Exit")
           break
           ;;
         *) echo invalid option;;
       esac
    done
}

optionsMenu
