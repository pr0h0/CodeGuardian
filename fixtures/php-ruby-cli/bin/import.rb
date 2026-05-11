require "open3"

cmd = ARGV[0]
safe = cmd
Open3.capture3(safe)
