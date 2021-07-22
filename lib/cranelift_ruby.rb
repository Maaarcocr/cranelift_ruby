# frozen_string_literal: true

require "cranelift_ruby/version"
require "rutie"

module CraneliftRuby
  Rutie.new(:cranelift_ruby).init "Init_cranelift_ruby", __dir__
end
