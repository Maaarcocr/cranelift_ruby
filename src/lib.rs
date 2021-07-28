#[macro_use]
extern crate rutie;

#[macro_use]
extern crate lazy_static;

use std::convert::TryInto;
use std::num::TryFromIntError;

use cranelift::codegen::binemit::{NullStackMapSink, NullTrapSink};
use cranelift::codegen::ir::{Inst, SigRef};
use cranelift::codegen::settings::{self, Configurable};
use cranelift::prelude::*;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{default_libcall_names, FuncId, Linkage, Module};
use eyre::{eyre, Result};
use rutie::{
    AnyException, AnyObject, Array, Class, Exception, Integer, NilClass, Object, Proc, RString,
    Symbol, VM,
};
class!(Cranelift);

pub struct Builder {
    pub module: JITModule,
}

impl Builder {
    fn new() -> Result<Self> {
        let mut flag_builder = settings::builder();
        flag_builder.set("use_colocated_libcalls", "false")?;
        // FIXME set back to true once the x64 backend supports it.
        flag_builder.set("is_pic", "false")?;
        let isa_builder = cranelift_native::builder()
            .map_err(|e| eyre!("Host machine is not supported. Error: {}", e))?;
        let isa = isa_builder.finish(settings::Flags::new(flag_builder));
        Ok(Self {
            module: JITModule::new(JITBuilder::with_isa(isa, default_libcall_names())),
        })
    }
}

wrappable_struct!(Builder, BuilderWrapper, BUILDER_WRAPPER);

class!(CraneliftBuilder);

methods!(
    CraneliftBuilder,
    itself,
    fn make_signature(params: Array, returns: Array) -> AnyObject {
        let builder = itself.get_data(&*BUILDER_WRAPPER);
        let params = params.map_err(|e| VM::raise_ex(e)).unwrap();
        let returns = returns.map_err(|e| VM::raise_ex(e)).unwrap();
        let sig = make_signature_impl(params, returns, &builder.module)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();

        Class::from_existing("CraneliftRuby")
            .get_nested_class("Signature")
            .wrap_data(sig, &*SIGNATURE_WRAPPER)
    },
    fn cranelift_builder_new() -> AnyObject {
        let builder = Builder::new()
            .map_err(|e| VM::raise_ex(AnyException::new("StandardError", Some(&e.to_string()))))
            .unwrap();
        Class::from_existing("CraneliftRuby")
            .get_nested_class("CraneliftBuilder")
            .wrap_data(builder, &*BUILDER_WRAPPER)
    },
    fn make_function(name: RString, signature: AnyObject, callback: Proc) -> Integer {
        let builder = itself.get_data_mut(&*BUILDER_WRAPPER);
        let name = name.map_err(|e| VM::raise_ex(e)).unwrap();
        let signature = signature.map_err(|e| VM::raise_ex(e)).unwrap();
        let signature = signature.get_data(&*SIGNATURE_WRAPPER);
        let callback = callback.map_err(|e| VM::raise_ex(e)).unwrap();
        let func_id = make_function_impl(name.to_str(), signature, callback, builder)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        Integer::new(func_id.into())
    },
    fn finalize() -> NilClass {
        let builder = itself.get_data_mut(&*BUILDER_WRAPPER);
        builder.module.finalize_definitions();
        NilClass::new()
    },
    fn get_function_pointer(func_id: Integer) -> Integer {
        let builder = itself.get_data_mut(&*BUILDER_WRAPPER);
        let func_id = func_id.map_err(|e| VM::raise_ex(e)).unwrap();
        let func_id = func_id
            .to_i64()
            .try_into()
            .map_err(|_e| {
                VM::raise_ex(AnyException::new(
                    "StandardError",
                    Some("Could create function id due to bad conversion"),
                ))
            })
            .unwrap();
        let func_id = FuncId::new(func_id);
        Integer::new(builder.module.get_finalized_function(func_id) as i64)
    }
);

fn map_symbol_to_type(symbol: Symbol) -> Result<types::Type, AnyException> {
    let s = symbol.to_str();
    if s == "I8" {
        Ok(types::I8)
    } else if s == "I16" {
        Ok(types::I16)
    } else if s == "I32" {
        Ok(types::I32)
    } else if s == "I64" {
        Ok(types::I64)
    } else {
        Err(AnyException::new(
            "StandardError",
            Some("The type for a param or a return is unknown"),
        ))
    }
}

fn make_signature_impl(
    params: Array,
    returns: Array,
    module: &JITModule,
) -> Result<Signature, AnyException> {
    let mut sig = module.make_signature();
    for param in params {
        let param = param.try_convert_to::<Symbol>()?;
        let ty = map_symbol_to_type(param)?;
        sig.params.push(AbiParam::new(ty));
    }

    for ret in returns {
        let ret = ret.try_convert_to::<Symbol>()?;
        let ty = map_symbol_to_type(ret)?;
        sig.returns.push(AbiParam::new(ty));
    }
    Ok(sig)
}

fn make_function_impl(
    name: &str,
    signature: &Signature,
    callback: Proc,
    builder: &mut Builder,
) -> Result<u32, AnyException> {
    let func = builder
        .module
        .declare_function(name, Linkage::Local, &signature)
        .map_err(|e| AnyException::new("StandardError", Some(&e.to_string())))?;
    let mut ctx = builder.module.make_context();
    let mut func_ctx = FunctionBuilderContext::new();
    ctx.func.signature = signature.clone();
    ctx.func.name = ExternalName::user(0, func.as_u32());
    // ctx.set_disasm(true);
    let bcx: FunctionBuilder = FunctionBuilder::new(&mut ctx.func, &mut func_ctx);
    let cranelift_bcx: AnyObject = Class::from_existing("CraneliftRuby")
        .get_nested_class("CraneliftFunctionBuilder")
        .wrap_data(bcx, &*FUNCTION_BUILDER_WRAPPER);
    callback.call(&[cranelift_bcx]);
    let mut trap_sink = NullTrapSink {};
    let mut stack_map_sink = NullStackMapSink {};
    // println!("{}", ctx.func.display(None).to_string());
    builder
        .module
        .define_function(func, &mut ctx, &mut trap_sink, &mut stack_map_sink)
        .map_err(|e| AnyException::new("StandardError", Some(&format!("{:?}", e))))?;
    // println!("code: {}", ctx.mach_compile_result.unwrap().disasm.unwrap());
    Ok(func.as_u32())
}

wrappable_struct!(Signature, SignatureWrapper, SIGNATURE_WRAPPER);
wrappable_struct!(Block, BlockWrapper, BLOCK_WRAPPER);

wrappable_struct!(
    FunctionBuilder<'static>,
    FunctionBuilderWrapper,
    FUNCTION_BUILDER_WRAPPER
);

class!(CraneliftFunctionBuilder);

methods!(
    CraneliftFunctionBuilder,
    itself,
    fn create_block() -> AnyObject {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let block = bcx.create_block();
        Class::from_existing("CraneliftRuby")
            .get_nested_class("Block")
            .wrap_data(block, &*BLOCK_WRAPPER)
    },
    fn append_block_params_for_function_params(block: AnyObject) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let block = block.map_err(|e| VM::raise_ex(e)).unwrap();
        let block = block.get_data(&*BLOCK_WRAPPER);
        bcx.append_block_params_for_function_params(*block);
        NilClass::new()
    },
    fn switch_to_block(block: AnyObject) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let block = block.map_err(|e| VM::raise_ex(e)).unwrap();
        let block = block.get_data(&*BLOCK_WRAPPER);
        bcx.switch_to_block(*block);
        NilClass::new()
    },
    fn declare_var(variable: AnyObject, ty: Symbol) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let variable = variable.map_err(|e| VM::raise_ex(e)).unwrap();
        let variable = variable.get_data(&*VARIABLE_WRAPPER);
        let ty = ty.map_err(|e| VM::raise_ex(e)).unwrap();
        let ty = map_symbol_to_type(ty).map_err(|e| VM::raise_ex(e)).unwrap();
        bcx.declare_var(*variable, ty);
        NilClass::new()
    },
    fn use_var(variable: AnyObject) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let variable = variable.map_err(|e| VM::raise_ex(e)).unwrap();
        let variable = variable.get_data(&*VARIABLE_WRAPPER);
        let val = bcx.use_var(*variable);
        Integer::new(val.as_u32().into())
    },
    fn def_var(variable: AnyObject, value: Integer) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let variable = variable.map_err(|e| VM::raise_ex(e)).unwrap();
        let variable = variable.get_data(&*VARIABLE_WRAPPER);
        let value = value.map_err(|e| VM::raise_ex(e)).unwrap();
        let value = from_integer_to_value(value)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        bcx.def_var(*variable, value);
        NilClass::new()
    },
    fn block_param(block: AnyObject, index: Integer) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let block = block.map_err(|e| VM::raise_ex(e)).unwrap();
        let index = index.map_err(|e| VM::raise_ex(e)).unwrap();

        let block = block.get_data(&*BLOCK_WRAPPER);
        let param = bcx.block_params(*block)[index.to_u64() as usize];
        Integer::new(param.as_u32().into())
    },
    fn import_signature(signature: AnyObject) -> AnyObject {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);

        let signature = signature.map_err(|e| VM::raise_ex(e)).unwrap();
        let signature = signature.get_data(&*SIGNATURE_WRAPPER);
        let sigref = bcx.import_signature(signature.clone());
        Class::from_existing("CraneliftRuby")
            .get_nested_class("SigRef")
            .wrap_data(sigref, &*SIGREF_WRAPPER)
    }
    fn call_indirect(sigref: AnyObject, callee: Integer, args: Array) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);

        let sigref = sigref.map_err(|e| VM::raise_ex(e)).unwrap();
        let sigref = sigref.get_data(&*SIGREF_WRAPPER);
        let callee = callee.map_err(|e| VM::raise_ex(e)).unwrap();
        let callee = from_integer_to_value(callee).map_err(|e| VM::raise_ex(e)).unwrap();
        let args = args.map_err(|e| VM::raise_ex(e)).unwrap();
        let args = from_array_to_values(args).map_err(|e| VM::raise_ex(e)).unwrap();
        let res = bcx.ins().call_indirect(*sigref, callee, &args);
        Integer::new(res.as_u32().into())
    }
    fn inst_results(inst: Integer) -> Array {
        let mut result = Array::new();
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let inst = inst.map_err(|e| VM::raise_ex(e)).unwrap();
        let inst = from_integer_to_inst(inst).map_err(|e| VM::raise_ex(e)).unwrap();
        let values = bcx.inst_results(inst);
        for value in values {
            result.push(Integer::new(value.as_u32().into()));
        }
        result
    }
    fn iconst(ty: Symbol, value: Integer) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let ty = ty.map_err(|e| VM::raise_ex(e)).unwrap();
        let ty = map_symbol_to_type(ty).map_err(|e| VM::raise_ex(e)).unwrap();
        let value = value.map_err(|e| VM::raise_ex(e)).unwrap();
        let res = bcx.ins().iconst(ty, value.to_i64());
        Integer::new(res.as_u32().into())
    },
    fn load(ty: Symbol, addr: Integer, offset: Integer) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let ty = ty.map_err(|e| VM::raise_ex(e)).unwrap();
        let ty = map_symbol_to_type(ty).map_err(|e| VM::raise_ex(e)).unwrap();
        let addr = addr.map_err(|e| VM::raise_ex(e)).unwrap();
        let addr = addr
            .to_u64()
            .try_into()
            .map_err(|e: TryFromIntError| {
                VM::raise_ex(AnyException::new("StandardError", Some(&e.to_string())))
            })
            .unwrap();
        let offset = offset.map_err(|e| VM::raise_ex(e)).unwrap();
        let res = bcx.ins().load(
            ty,
            MemFlags::trusted(),
            Value::from_u32(addr),
            offset.to_i32(),
        );
        Integer::new(res.as_u32().into())
    },
    fn store(value: Integer, addr: Integer, offset: Integer) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let addr = addr.map_err(|e| VM::raise_ex(e)).unwrap();
        let addr = addr
            .to_u64()
            .try_into()
            .map_err(|e: TryFromIntError| {
                VM::raise_ex(AnyException::new("StandardError", Some(&e.to_string())))
            })
            .unwrap();
        let value = value.map_err(|e| VM::raise_ex(e)).unwrap();
        let value = value
            .to_u64()
            .try_into()
            .map_err(|e: TryFromIntError| {
                VM::raise_ex(AnyException::new("StandardError", Some(&e.to_string())))
            })
            .unwrap();
        let offset = offset.map_err(|e| VM::raise_ex(e)).unwrap();
        bcx.ins().store(
            MemFlags::trusted(),
            Value::from_u32(value),
            Value::from_u32(addr),
            offset.to_i32(),
        );
        NilClass::new()
    },
    fn iadd(x: Integer, y: Integer) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let x = x.map_err(|e| VM::raise_ex(e)).unwrap();
        let x = from_integer_to_value(x)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let y = y.map_err(|e| VM::raise_ex(e)).unwrap();
        let y = from_integer_to_value(y)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();

        let res = bcx.ins().iadd(x, y);
        Integer::new(res.as_u32().into())
    },
    fn band(x: Integer, y: Integer) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let x = x.map_err(|e| VM::raise_ex(e)).unwrap();
        let x = from_integer_to_value(x)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let y = y.map_err(|e| VM::raise_ex(e)).unwrap();
        let y = from_integer_to_value(y)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();

        let res = bcx.ins().band(x, y);
        Integer::new(res.as_u32().into())
    },
    fn bor(x: Integer, y: Integer) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let x = x.map_err(|e| VM::raise_ex(e)).unwrap();
        let x = from_integer_to_value(x)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let y = y.map_err(|e| VM::raise_ex(e)).unwrap();
        let y = from_integer_to_value(y)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();

        let res = bcx.ins().bor(x, y);
        Integer::new(res.as_u32().into())
    },
    fn return_(values: Array) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let values = values.map_err(|e| VM::raise_ex(e)).unwrap();
        let mut return_value: Vec<Value> = from_array_to_values(values)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        bcx.ins().return_(&return_value);
        NilClass::new()
    },
    fn jump(block: AnyObject, args: Array) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let block = block.map_err(|e| VM::raise_ex(e)).unwrap();
        let block = block.get_data(&*BLOCK_WRAPPER);
        let args = args.map_err(|e| VM::raise_ex(e)).unwrap();
        let args = from_array_to_values(args)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        bcx.ins().jump(*block, &args);
        NilClass::new()
    },
    fn brz(value: Integer, block: AnyObject, args: Array) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let block = block.map_err(|e| VM::raise_ex(e)).unwrap();
        let block = block.get_data(&*BLOCK_WRAPPER);
        let args = args.map_err(|e| VM::raise_ex(e)).unwrap();
        let args = from_array_to_values(args)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let value = value.map_err(|e| VM::raise_ex(e)).unwrap();
        let value = from_integer_to_value(value)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        bcx.ins().brz(value, *block, &args);
        NilClass::new()
    },
    fn brnz(value: Integer, block: AnyObject, args: Array) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let block = block.map_err(|e| VM::raise_ex(e)).unwrap();
        let block = block.get_data(&*BLOCK_WRAPPER);
        let args = args.map_err(|e| VM::raise_ex(e)).unwrap();
        let args = from_array_to_values(args)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let value = value.map_err(|e| VM::raise_ex(e)).unwrap();
        let value = from_integer_to_value(value)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        bcx.ins().brnz(value, *block, &args);
        NilClass::new()
    },
    fn br_icmp(cond: Symbol, x: Integer, y: Integer, block: AnyObject, args: Array) -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let block = block.map_err(|e| VM::raise_ex(e)).unwrap();
        let block = block.get_data(&*BLOCK_WRAPPER);
        let args = args.map_err(|e| VM::raise_ex(e)).unwrap();
        let args = from_array_to_values(args)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let x = x.map_err(|e| VM::raise_ex(e)).unwrap();
        let x = from_integer_to_value(x)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let y = y.map_err(|e| VM::raise_ex(e)).unwrap();
        let y = from_integer_to_value(y)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let cond = cond.map_err(|e| VM::raise_ex(e)).unwrap();
        let cond = from_symbol_to_icc(cond)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        bcx.ins().br_icmp(cond, x, y, *block, &args);
        NilClass::new()
    },
    fn icmp(cond: Symbol, x: Integer, y: Integer) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let x = x.map_err(|e| VM::raise_ex(e)).unwrap();
        let x = from_integer_to_value(x)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let y = y.map_err(|e| VM::raise_ex(e)).unwrap();
        let y = from_integer_to_value(y)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let cond = cond.map_err(|e| VM::raise_ex(e)).unwrap();
        let cond = from_symbol_to_icc(cond)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let res = bcx.ins().icmp(cond, x, y);
        Integer::new(res.as_u32().into())
    },
    fn select(cond: Integer, x: Integer, y: Integer) -> Integer {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        let x = x.map_err(|e| VM::raise_ex(e)).unwrap();
        let x = from_integer_to_value(x)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let y = y.map_err(|e| VM::raise_ex(e)).unwrap();
        let y = from_integer_to_value(y)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let cond = cond.map_err(|e| VM::raise_ex(e)).unwrap();
        let cond = from_integer_to_value(cond)
            .map_err(|e| VM::raise_ex(e))
            .unwrap();
        let res = bcx.ins().select(cond, x, y);
        Integer::new(res.as_u32().into())
    },
    fn finalize_function() -> NilClass {
        let bcx = itself.get_data_mut(&*FUNCTION_BUILDER_WRAPPER);
        bcx.seal_all_blocks();
        bcx.finalize();
        NilClass::new()
    }
);

fn from_symbol_to_icc(symbol: Symbol) -> Result<IntCC, AnyException> {
    let s = symbol.to_str();
    if s == "e" {
        Ok(IntCC::Equal)
    } else if s == "ne" {
        Ok(IntCC::NotEqual)
    } else if s == "sg" {
        Ok(IntCC::SignedGreaterThan)
    } else if s == "sge" {
        Ok(IntCC::SignedGreaterThanOrEqual)
    } else if s == "sle" {
        Ok(IntCC::SignedLessThanOrEqual)
    } else if s == "sl" {
        Ok(IntCC::SignedLessThan)
    } else if s == "ug" {
        Ok(IntCC::UnsignedGreaterThan)
    } else if s == "uge" {
        Ok(IntCC::UnsignedGreaterThanOrEqual)
    } else if s == "ule" {
        Ok(IntCC::UnsignedLessThanOrEqual)
    } else if s == "ul" {
        Ok(IntCC::UnsignedLessThan)
    } else if s == "overflow" {
        Ok(IntCC::Overflow)
    } else if s == "not_overflow" {
        Ok(IntCC::NotOverflow)
    } else {
        Err(AnyException::new(
            "StandardError",
            Some("The type for a param or a return is unknown"),
        ))
    }
}

fn from_integer_to_value(i: Integer) -> Result<Value, AnyException> {
    Ok(Value::from_u32(i.to_i32().try_into().map_err(|_e| {
        AnyException::new("StandardError", Some("Could not conver int to u32"))
    })?))
}

fn from_integer_to_inst(i: Integer) -> Result<Inst, AnyException> {
    Ok(Inst::from_u32(i.to_i32().try_into().map_err(|_e| {
        AnyException::new("StandardError", Some("Could not conver int to u32"))
    })?))
}

fn from_array_to_values(array: Array) -> Result<Vec<Value>, AnyException> {
    let mut return_values: Vec<Value> = Vec::new();
    for value in array {
        let value = value.try_convert_to::<Integer>()?;
        let value = value.to_i32().try_into().map_err(|_e| {
            AnyException::new("StandardError", Some("Could not conver int to u32"))
        })?;
        return_values.push(Value::from_u32(value));
    }
    Ok(return_values)
}

wrappable_struct!(Variable, VariableWrapper, VARIABLE_WRAPPER);
wrappable_struct!(SigRef, SigRefWrapper, SIGREF_WRAPPER);


class!(CraneliftVariable);

methods!(
    CraneliftVariable,
    _itself,
    fn new_cranelift_variable(index: Integer) -> AnyObject {
        let index = index.map_err(|e| VM::raise_ex(e)).unwrap();
        let var = Variable::new(
            index
                .to_i64()
                .try_into()
                .map_err(|_e| {
                    VM::raise_ex(AnyException::new(
                        "StandardError",
                        Some("Could not convert to usize"),
                    ))
                })
                .unwrap(),
        );
        Class::from_existing("CraneliftRuby")
            .get_nested_class("Variable")
            .wrap_data(var, &*VARIABLE_WRAPPER)
    }
);

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Init_cranelift_ruby() {
    let data_class = Class::from_existing("Object");
    rutie::Module::from_existing("CraneliftRuby").define(|itself| {
        itself
            .define_nested_class("CraneliftBuilder", Some(&data_class))
            .define(|klass| {
                klass.def_self("new", cranelift_builder_new);
                klass.def("make_signature", make_signature);
                klass.def("make_function", make_function);
                klass.def("finalize", finalize);
                klass.def("get_function_pointer", get_function_pointer);
            });
        itself.define_nested_class("Signature", Some(&data_class));
        itself.define_nested_class("SigRef", Some(&data_class));
        itself.define_nested_class("Block", Some(&data_class));
        itself
            .define_nested_class("Variable", Some(&data_class))
            .define(|klass| {
                klass.def_self("new", new_cranelift_variable);
            });
        itself
            .define_nested_class("CraneliftFunctionBuilder", Some(&data_class))
            .define(|klass| {
                klass.def("create_block", create_block);
                klass.def("switch_to_block", switch_to_block);
                klass.def("block_param", block_param);
                klass.def(
                    "append_block_params_for_function_params",
                    append_block_params_for_function_params,
                );
                klass.def("return", return_);
                klass.def("iconst", iconst);
                klass.def("iadd", iadd);
                klass.def("load", load);
                klass.def("store", store);
                klass.def("jump", jump);
                klass.def("brz", brz);
                klass.def("brnz", brnz);
                klass.def("br_icmp", br_icmp);
                klass.def("finalize", finalize_function);
                klass.def("declare_var", declare_var);
                klass.def("def_var", def_var);
                klass.def("use_var", use_var);
                klass.def("icmp", icmp);
                klass.def("select", select);
                klass.def("import_signature", import_signature);
                klass.def("call_indirect", call_indirect);
                klass.def("inst_results", inst_results);
                klass.def("band", band);
                klass.def("bor", bor);
            });
    });
}
