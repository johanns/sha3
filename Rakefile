# encoding: utf-8

require 'rubygems'
require 'rake'

begin
  gem 'rubygems-tasks'
  require 'rubygems/tasks'

  Gem::Tasks.new
rescue LoadError => e
  warn e.message
  warn "Run `gem install rubygems-tasks` to install Gem::Tasks."
end

begin
  gem 'rspec', '~> 3.3'
  require 'rspec/core/rake_task'

  RSpec::Core::RakeTask.new
rescue LoadError => e
  task :spec do
    abort "Please run `gem install rspec` to install RSpec."
  end
end

task :test    => :spec
task :default => [:compile, :spec]

begin
  gem 'yard'
  require 'yard'

  YARD::Rake::YardocTask.new
rescue LoadError => e
  task :yard do
    abort "Please run `gem install yard` to install YARD."
  end
end
task :doc => :yard

begin
  gem 'rake-compiler'
  require 'rake/extensiontask'

  Rake::ExtensionTask.new do |ext|
    ext.name = 'sha3_n'
    ext.ext_dir = 'ext/sha3'
    ext.tmp_dir = 'tmp'
    ext.source_pattern = "*.{c}"
  end
rescue LoadError => e
  task :compile do
    abort "Please run `gem install rake-compiler` to install Rake-Compiler."
  end
end
