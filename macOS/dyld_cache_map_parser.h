#include <map>
#include <string>
#include <vector>

std::map<std::string, std::vector<std::string>> parse_dyld_map_file(const std::string &path);
