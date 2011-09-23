require 'rake'
require 'rake/testtask'

task :default => :test

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new("coverage") do |rcov|
    rcov.libs << 'lib'
    rcov.pattern = 'test/test_*.rb'
  end
rescue LoadError
end

Rake::TestTask.new("test") do |test|
  test.libs << 'lib'
  test.verbose = true
  test.test_files = Dir.glob('test/test_*.rb')
end
