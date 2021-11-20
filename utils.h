uint64_t get_ts_ms();
uint64_t get_us();

void setlog(const std::string & file, const bool fs);
void dolog(const char *fmt, ...);

std::string myformat(const char *const fmt, ...);
std::vector<std::string> * split(std::string in, std::string splitter);

bool isBigEndian();
