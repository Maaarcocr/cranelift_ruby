# frozen_string_literal: true

require "rbconfig"
require "bundler/gem_tasks"
require "rake/testtask"

# Mac OS with rbenv users keep leaving behind build artifacts from
#   when they tried to build against a statically linked Ruby and then
#   try against a dynamically linked one causing errors in the build result.
desc "Preventative work"
task :tidy_up do
  sh "cargo clean"
end

desc "Build Rust extension"
task :build_lib do
  sh "cargo build --release"
end

desc "bundle install"
task :bundle_install do
  sh "bundle install"
end

Rake::TestTask.new(test: %i[]) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

Rake::TestTask.new(test_clean: %i[tidy_up bundle_install build_lib]) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

task default: :test_clean
