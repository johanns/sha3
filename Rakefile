# frozen_string_literal: true

require 'bundler/gem_tasks'

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec)

require 'rubocop/rake_task'
RuboCop::RakeTask.new

require 'rake/extensiontask'

begin
  Rake::ExtensionTask.new :compile do |ext|
    ext.name = 'sha3_ext'

    ext.ext_dir = 'ext/sha3'
    ext.source_pattern = '*.{c}'
    ext.tmp_dir = 'tmp'
  end
rescue LoadError
  task :compile do
    abort 'Please run `gem install rake-compiler` to install Rake-Compiler.'
  end
end

require 'rdoc/task'

RDoc::Task.new do |rdoc|
  rdoc.rdoc_dir = '../docs/sha3'
  rdoc.options << '--force-update'
  rdoc.options << '-V'
end

task default: %i[compile spec]
