#include "macOS/dyld_cache_map_parser.h"

#include <iostream>
#include <fstream>
#include <regex>

#include "common.h"

struct Module {
  Module(std::string n, uint64_t s, uint64_t e)
  : name(n), start(s), end(e) {}
  std::string name;
  uint64_t start;
  uint64_t end;
};

static bool is_page_aligned(uint64_t addr, uint64_t page_size = 0x4000) {
  return !(addr & (page_size-1));
}

std::map<std::string, std::vector<std::string>> parse_dyld_map_file(const std::string &path) {
  std::ifstream cache_map(path);
  std::string line;

  std::map<std::string, std::vector<std::string>> result;
  std::map<uint64_t, Module> tmp_result;

  std::string regex = "__TEXT 0x([A-F0-9]+) -> 0x([A-F0-9]+)";
  std::smatch m;
  std::regex r(regex);


  bool lib = false;
  int i = 0;
  std::string lib_name;
  while (std::getline(cache_map, line)) {
    if (line.length() > 0 && line[0] == '/') {
      lib = true;
      if (line.rfind("/") == std::string::npos) {
        std::cout << "error\n";
        std::cout << line << "\n";
        return {};
      }
      lib_name = line.substr(line.rfind("/") + 1);
    }

    if (lib && line.length() == 0) {
      lib = false;
    }

    if (lib) {
      if(std::regex_search(line, m, r)) {
        if(m.size() != 3) continue;
        uint64_t start = std::stoul(m[1], nullptr, 16);
        uint64_t end = std::stoul(m[2], nullptr, 16);
        tmp_result.insert({start, Module(lib_name, start, end)});
      }
    }
  }

  uint64_t prev_end_addr = tmp_result.begin()->second.start;
  std::vector<std::string> mod_group;
  for(const auto &[start_address, mod]: tmp_result) {
    mod_group.push_back(mod.name);

    if(is_page_aligned(mod.end)) {
      for(const auto mod_name: mod_group) {
        result.insert({mod_name, mod_group});
      }

      mod_group.clear();
      prev_end_addr = mod.end;  
    }
    else if(prev_end_addr != mod.start && is_page_aligned(mod.start)) {
      mod_group.pop_back();

      for(const auto mod_name: mod_group) {
        result.insert({mod_name, mod_group});
      }

      mod_group.clear();   
      mod_group.push_back(mod.name);
    }
    else {
      prev_end_addr = mod.end;
    }
  }

  cache_map.close();
  return result;
}
