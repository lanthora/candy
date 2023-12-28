#!/bin/bash -e

# Define an array to store the processed dependencies
declare -a processed

# Define a function to get the whole list of dependencies recursively
get_the_whole_list_of_dependencies () {

  # Use ldd to list the dependencies and filter out the ones that are not absolute paths
  local list=$(ldd "$1" | awk '/=> \// {print $3}')

  # Loop through the dependencies
  for dep in $list; do

    # Check if the dependency has been processed before
    if [[ ! " ${processed[@]} " =~ " ${dep} " ]]; then

      # Check if the dependency contains /c/Windows in its path
      if [[ "$dep" =~ "/c/Windows" ]]; then
        # Ignore the dependency and continue the loop
        continue
      fi

      # Show the dependency
      echo "$dep"

      # Add the dependency to the processed array
      processed+=("$dep")

      # Recursively call the function to process the dependency's dependencies
      get_the_whole_list_of_dependencies "$dep"
    fi
  done
}

# Check if the executable file is given as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <PATH>"
  exit 1
fi

# Get the absolute path of the executable file
exe=$(readlink -f "$1")

# Call the function to get the whole list of dependencies recursively
get_the_whole_list_of_dependencies "$exe"
