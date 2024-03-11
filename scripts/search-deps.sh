#!/bin/bash -e

# Define an array to store the processed dependencies
declare -a processed

# Define a function to get the whole list of dependencies recursively
recursive_search_deps () {
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

      # If there are two arguments, copy the dependency to the specified directory
      if [ "$#" -eq 2 ]; then
        # Copy the dependency to the specified directory
        cp "$dep" "$2"
        # Output the copied file path and name
        echo "Copied $dep to $2/"
      else
        # Show the dependency
        echo "$dep"
      fi

      # Add the dependency to the processed array
      processed+=("$dep")

      # Recursively call the function to process the dependency's dependencies
      recursive_search_deps "$dep" ${2:-}
    fi
  done
}

# Check if the executable file is given as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <PATH> [DESTINATION]"
  exit 1
fi

# If there are two arguments, check if the directory exists before proceeding
if [ "$#" -eq 2 ]; then
  if [ ! -d "$2" ]; then
    echo "Error: Directory $2 does not exist."
    exit 1
  fi
fi

# Get the absolute path of the executable file
exe=$(readlink -f "$1")

# Call the function to get the whole list of dependencies recursively
recursive_search_deps "$exe" ${2:-}
