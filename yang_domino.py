#!/usr/bin/env python3.6
#
# YANG Domino
# (C) 2020 Cisco Systems, Jan Lindblad <jlindbla@cisco.com>

import os, sys, getopt, pathlib, shutil, subprocess

def _strip_version(filename):
  if not '@' in filename:
    return filename
  return filename.split('@')[0]

def scan_yanger(files_to_scan, path="."):
  dependency_map = {}
  incompletely_scanned = set()
  for file in files_to_scan:
    result = subprocess.run(["yanger", "-f", "depend", "-p", ":".join(path), file], #"--depend-include-path"
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, universal_newlines=True)

    #print(f'YY files={files_to_scan} out={result.stdout} err={result.stderr}')
    for line in result.stdout.split('\n'):
      # Line format:
      # Cisco-IOS-XR-ifmgr-oper.yang : Cisco-IOS-XR-types cisco-semver Cisco-IOS-XR-ifmgr-oper-sub2 Cisco-IOS-XR-ifmgr-oper-sub1
      piece = line.split(" ")
      if len(piece) < 2 or piece[1] != ":":
        #print(f"## Skipping oddly formatted line '{line}'")
        continue
      name = _strip_version(os.path.splitext(os.path.basename(piece[0]))[0])
      dependency_map[name] = piece[2:]
      #print(f'YY {name} {piece[2:]} {dependency_map}')

    for line in result.stderr.split('\n'):
      # Line format:
      # ./ietf-network-topology.yang:11: error: module 'ietf-network' not found
      # ./ietf-packet-fields.yang:18: error: module 'ietf-ethertypes' not found
      piece = line.split(":")
      if len(piece) < 4 or piece[2] != " error":
        #print(f"## Skipping oddly formatted line '{line}'")
        continue
      name = _strip_version(os.path.splitext(os.path.basename(piece[0]))[0])
      missing_mod = [piece[3].split("'")[1]]
      dependency_map[name] = dependency_map.get(name,[]) + missing_mod
      #print(f"## Acting on '{line}' => missing mod {missing_mod}")
      incompletely_scanned.add(file) # Import statements not read, since there was an error
      #print(f'YE {name} {missing_mod} {dependency_map}')
  return (incompletely_scanned, dependency_map)

def scan_grep(files_to_scan):
  result = subprocess.run(["egrep", "^[ \t]*(import|include) .*[{;]"] + files_to_scan, 
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, universal_newlines=True)
  dependency_map = {}
  for file in files_to_scan:
    name = os.path.splitext(_strip_version(os.path.basename(file))[0])
    dependency_map[name] = []
  for line in result.stdout.split('\n'):
    # Line format:
    # Cisco-IOS-XR-ipv4-vrrp-cfg.yang:  import Cisco-IOS-XR-types {
    # Cisco-IOS-XR-ipv4-vrrp-cfg.yang:  import cisco-semver {
    piece = line.split(":")
    if len(piece) != 2:
      #print(f"## Skipping oddly formatted line '{line}'")
      continue
    name = os.path.splitext(os.path.basename(piece[0]))[0]
    dep = piece[1]
    dep = dep.replace("import", "")
    dep = dep.replace("include", "")
    end = dep.find("{")
    if not end:
      end = dep.find(";")
    dep = dep[:end]
    dep = dep.strip()
    dependency_map[name] += [dep]
  return (set(), dependency_map)

def module_find(module_name, module_dirs, recursive=False, verbose=False):
  selected_module_location = None
  found_module_count = 0
  for dir_name in module_dirs:
    p = pathlib.Path(dir_name)
    yang_mods = list(p.glob('**/*.yang' if recursive else '*.yang'))
    #print(f"yang_mods {yang_mods} module_name {module_name}")
    for yang_mod in yang_mods:
      if yang_mod.name.startswith(module_name+'@') or yang_mod.name.startswith(module_name+'.yang'):
        found_module_count += 1
        if verbose: print(f"{module_name} : #{found_module_count}: Candidate match in library {yang_mod}")
    mod_path = [yang_mod for yang_mod in yang_mods if yang_mod.name.startswith(module_name+'@') or yang_mod.name.startswith(module_name+'.yang')]
    if len(mod_path) > 0 and not selected_module_location:
      selected_module_location = mod_path[0]
  #if verbose: print(f"{module_name} : found {found_module_count}")
  return selected_module_location

def domino(files_to_scan, forbidden_files, dependency_map):
  #print(f"map={dependency_map}")
  good_set = set([_strip_version(os.path.splitext(file)[0]) for file in files_to_scan])
  bad_set = set([_strip_version(os.path.splitext(file)[0]) for file in forbidden_files])
  for file in bad_set:
    if file in good_set:
      # If the file is both in the good and bad set, it's a bad file
      good_set.remove(file)
  return _domino(good_set, bad_set, dependency_map)

def _domino(good_set, bad_set, dependency_map):
  root_cause_map = {}
  change = True
  while change:
    change = False
    for file in set(good_set):
      for dep in dependency_map[file]:
        if dep in bad_set:
          if file in good_set:
            good_set.remove(file)
          bad_set.add(file)
          if file not in root_cause_map:
            root_cause_map[file] = set()
          if dep in root_cause_map:
            root_cause_map[file] = root_cause_map[file].union(root_cause_map[dep])
          else:
            root_cause_map[file] = root_cause_map[file].union(set([dep]))
          change = True
  return (good_set, bad_set, root_cause_map)

def usage():
  print(f'''{sys.argv[0]} [--use-grep] 
    [-l | --library <module directory tree>]
    [-m | --modules <module directory>] [-e | --extra <fetched module directory] 
    [-r | --remove <module-to-remove>] 
    <modules-to-scan>
  Scans YANG modules for dependencies.

  and optionally fetch missing modules from source directory
  If --use-grep flag is specified, scanning is not syntax YANG aware, and may not be
  completely correct. Default us to use Yanger, a YANG compiler you need to install.''')

def main():
  debug = False
  remove_file_names = []
  library_dirs = []
  module_dirs = ["."]
  extra_dir = "."
  use_grep = False
  try:
    opts, args = getopt.gnu_getopt(sys.argv[1:],"h:r:l:m:e:",
      ["help", "debug", "use-grep", "remove=", "library=", "modules=", "extra="])
  except getopt.GetoptError:
    usage()
    sys.exit(2)
  for opt, arg in opts:
    if opt in ('-h', '--help'):
      usage()
      sys.exit()
    elif opt in ("-r", "--remove"):
      remove_file_names += [arg]
    elif opt in ("-l", "--library"):
      library_dirs += [arg]
    elif opt in ("-m", "--modules"):
      module_dirs += [arg]
    elif opt in ("-e", "--extra"):
      extra_dir = arg
    elif opt in ("--use-grep"):
      use_grep = True
    elif opt in ("--debug"):
      debug = True
    else:
      print('Unknown option "%s", exiting.'%opt)
      sys.exit(2)

  if extra_dir not in module_dirs:
    module_dirs += [extra_dir]

  files_to_scan = set(args)

  while files_to_scan:
    if debug: print(f'\n\nXX Files to scan: {files_to_scan}')
    if use_grep:
      (incomplete, dependency_map) = scan_grep(files_to_scan)
    else:
      (incomplete, dependency_map) = scan_yanger(files_to_scan, path=module_dirs)
    if debug: print(f'XX Dependency map: {dependency_map}')

    if remove_file_names:
      (good_set, bad_set, root_cause_map) = domino([pathlib.Path(f).name for f in files_to_scan], remove_file_names, dependency_map)
      if debug: print(f'XX Domino: GOOD {good_set}\n\nBAD {bad_set}\n\nROOT {root_cause_map}\n')
      bad_files = list(bad_set)
      bad_files.sort()
      for file in bad_files:
        if file in root_cause_map:
          print(f"""Bad {file} : {" ".join([fn for fn in root_cause_map[file]])}""")
        else:
          print(f"Rem {file}")
#    section_header = "## Domino YANG files depending on missing files : because of"
#    good_set = set([os.path.splitext(file)[0] for file in files_to_scan])
#    missing_deps = set()
#    for file in good_set:
#      #print(f'XX file={file} map={dependency_map} good={good_set}')
#      deps = [f"{dep}.yang" for dep in dependency_map.get(file,'') if dep and dep not in good_set]
#      if deps:
#        for dep in deps:
#          missing_deps.add(dep)
#          if section_header:
#            print(f"\n{section_header}\n")
#            section_header = None
#        print(f"""{file}.yang : {" ".join(deps)}""")
#
#    section_header = "## Missing imported or included YANG files"
#    if missing_deps:
#      missing_deps_list = list(missing_deps)
#      missing_deps_list.sort()
#      for dep in missing_deps_list:
#        if section_header:
#          print(f"\n{section_header}\n")
#          section_header = None
#        print(f"{dep}")

    files_to_scan = incomplete
    if debug: print(f'XX Files to scan again: {files_to_scan}')

    found_map = {}
    for importer in dependency_map:
      for imported_module in dependency_map[importer]:
        found_map[imported_module] = module_find(imported_module, module_dirs, recursive=False, verbose=debug)
    if debug: print(f'XX Files found: {found_map}')

    if not remove_file_names and not library_dirs:
      # Just scan for missing modules
      for importer in dependency_map:
        dep_str = ""
        missing_counter = 0
        for imported in dependency_map[importer]:
          dep_str += imported
          if not found_map[imported]:
            missing_counter += 1
            dep_str += '<MISSING> '
          else:
            dep_str += ' '
        status = "Ok "
        if missing_counter:
          status = f'{missing_counter:3}'
        print(f'{status} {importer} : {dep_str}')
      sys.exit(0)

    if library_dirs:
      # Copy missing modules from library
      if debug: print(f'XX Library dirs')
      for imported_module in [module for module in found_map if found_map[module] == None]:
        if debug: print(f'XX Locating: {imported_module}')
        found_map[imported_module] = module_find(imported_module, library_dirs, recursive=True)
        if found_map[imported_module]:
          try:
            dest_file = pathlib.Path(extra_dir,found_map[imported_module].name)
            shutil.copyfile(found_map[imported_module], dest_file)
            files_to_scan.add(dest_file)
            print(f'{imported_module} : Copied {found_map[imported_module]} to {dest_file}')
          except Exception as ex:
            print(f'{imported_module} : Unable to copy {found_map[imported_module]} to {pathlib.Path(extra_dir, found_map[imported_module].name)} : {ex}')
        else:
          print(f'{imported_module} : Unable to find module in any of the specified library directories')
      if debug: print(f'XX Library dirs done')


if __name__ == '__main__':
  main()
