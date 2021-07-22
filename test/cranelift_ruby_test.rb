require "test_helper"
require "fiddle"

class CraneliftRubyTest < Minitest::Test
  def test_it
    b = CraneliftRuby::CraneliftBuilder.new
    s = b.make_signature([:I64], [])
    f = b.make_function("test", s, -> (bcx) {
      block = bcx.create_block
      bcx.append_block_params_for_function_params(block)
      x = bcx.block_param(block, 0)
      bcx.switch_to_block(block)
      char = bcx.load(:I8, x, 0)
      cst = bcx.iconst(:I8, 1)
      res = bcx.iadd(char, cst)
      bcx.store(res, x, 0)
      match_index = CraneliftRuby::Variable.new(0)
      bcx.declare_var(match_index, :I64)
      initial_match_index_value = bcx.iconst(:I64, 0)
      bcx.def_var(match_index, initial_match_index_value)

      match_index_val = bcx.use_var(match_index)
      bcx.return([])
      bcx.finalize
    })
    b.finalize
    f_ptr = b.get_function_pointer(f)
    fun = Fiddle::Function.new(f_ptr, [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    x = "a"
    fun.call(x)
    assert_equal("b", x)
  end
end