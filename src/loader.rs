use std::cell::UnsafeCell;
use std::slice;

use xmas_elf as elf;
use xmas_elf::dynamic::Tag;

#[derive(Clone, Copy, Debug)]
struct ElfOffs(u32);

#[derive(Clone, Copy, Debug)]
struct ElfStr(u32);
impl ElfStr {
    fn to_str(self, obj: &Object) -> &str {
        let ElfStr(s_idx) = self;
        let elf = elf::ElfFile::new(&obj.buf.buf()).unwrap();
        elf.get_dyn_string(s_idx).unwrap()
    }
}

#[derive(Debug)]
struct Dynamic {
    deps: Vec<ElfStr>,
    jmprel: Option<RelocationTable>,
    rel: Option<RelocationTable>,
    rela: Option<RelocationTable>,
    strtab: Option<ElfOffs>,
    symtab: Option<SymbolTable>,
    hash: Option<ElfOffs>,
}

impl Dynamic {
    fn new(obj: &Object) -> Self {
        let elf = elf::ElfFile::new(&obj.buf.buf()).unwrap();

        let seg_data = elf.program_iter()
            .filter_map(|program| program.get_data(&elf).ok())
            .filter_map(|seg|
                if let elf::program::SegmentData::Dynamic32(dyn_data) = seg {
                    Some(dyn_data)
                } else { None }
            )
            .next()
            .unwrap();

        let mut dyn_data = Dynamic {
            deps: Vec::new(),
            jmprel: None,
            rel: None,
            rela: None,
            strtab: None,
            symtab: None,
            hash: None,
        };

        let mut jmprel_offs = None;
        let mut jmprel_type = None;
        let mut jmprel_size = None;

        let mut rel_offs = None;
        let mut rel_size = None;

        let mut rela_offs = None;
        let mut rela_size = None;

        let mut symtab_offs = None;

        for dynamic in seg_data {
            let tag = dynamic.get_tag();

            match tag {
                // Mandatory
                Ok(Tag::StrTab) => {
                    dyn_data.strtab = Some(ElfOffs(dynamic.get_ptr().unwrap()));
                }
                Ok(Tag::Hash) => {
                    dyn_data.hash = Some(ElfOffs(dynamic.get_ptr().unwrap()));
                }
                Ok(Tag::SymTab) => symtab_offs = dynamic.get_ptr().ok(),

                Ok(Tag::Needed) => {
                    let strent = dynamic.get_val().unwrap();
                    dyn_data.deps.push(ElfStr(strent));
                }

                Ok(Tag::JmpRel) => jmprel_offs = dynamic.get_ptr().ok(),
                Ok(Tag::PltRel) => jmprel_type = dynamic.get_val().ok(),
                Ok(Tag::PltRelSize) => jmprel_size = dynamic.get_val().ok(),

                Ok(Tag::Rel) => rel_offs = dynamic.get_ptr().ok(),
                Ok(Tag::RelSize) => rel_size = dynamic.get_val().ok(),

                Ok(Tag::Rela) => rela_offs = dynamic.get_ptr().ok(),
                Ok(Tag::RelaSize) => rela_size = dynamic.get_val().ok(),

                Ok(Tag::Null) => break,
                
                Err(s) => panic!("ERROR loading elf file: `{}`!", s),
                _ => {}
            }
        }

        assert!(dyn_data.hash.is_some());
        assert!(dyn_data.strtab.is_some());

        if let (Some(offs), Some(ty), Some(size)) = (jmprel_offs, jmprel_type, jmprel_size) {
            const DT_REL: u32 = 17;
            const DT_RELA: u32 = 7;

            dyn_data.jmprel = Some(RelocationTable {
                offs: ElfOffs(offs),
                ty: match ty {
                    DT_REL => RelEntTy::Rel,
                    DT_RELA => RelEntTy::Rela,
                    _ => unreachable!()
                },
                size: size as usize
            });
        }

        if let (Some(offs), Some(size)) = (rel_offs, rel_size) {
            dyn_data.rel = Some(RelocationTable {
                offs: ElfOffs(offs),
                ty: RelEntTy::Rel,
                size: size as usize
            });
        }

        if let (Some(offs), Some(size)) = (rela_offs, rela_size) {
            dyn_data.rela = Some(RelocationTable {
                offs: ElfOffs(offs),
                ty: RelEntTy::Rela,
                size: size as usize
            });
        }

        let nchain_offs = dyn_data.hash.unwrap().0 as usize + 4;
        let n_syments = obj.read32(nchain_offs);
        dyn_data.symtab = Some(SymbolTable {
            offs: ElfOffs(symtab_offs.unwrap()), // symtab is mandatory
            len: n_syments
        });


        dyn_data
    }

    fn hash(&self) -> HashTable {
        HashTable(self.hash.unwrap()) // hash is mandatory
    }

    fn strtab(&self) -> ElfOffs {
        self.strtab.unwrap() // strtab is mandatory
    }

    fn symtab(&self) -> SymbolTable {
        self.symtab.unwrap() // symtab is mandatory
    }
}


#[derive(Copy, Clone, Debug)]
struct Symbol(u32);

#[derive(Copy, Clone, Debug)]
struct HashTable(ElfOffs);

impl HashTable {
    fn n_bucket(&self, obj: &Object) -> usize {
        let HashTable(ElfOffs(offs)) = *self;
        obj.read32(offs as usize) as usize
    }

    fn n_chain(&self, obj: &Object) -> usize {
        let HashTable(ElfOffs(offs)) = *self;
        obj.read32(offs as usize + 4) as usize
    }

    fn index_buckets(&self, obj: &Object, idx: usize) -> u32 {
        let HashTable(ElfOffs(table)) = *self;
        let buckets = table + 8;
        obj.read32((buckets as usize) + idx * 4)
    }

    fn index_chain(&self, obj: &Object, idx: usize) -> u32 {
        let HashTable(ElfOffs(table)) = *self;
        let chain_array = (table as usize) + 8 + self.n_bucket(obj) * 4;
        obj.read32(chain_array + idx * 4)
    }

    fn follow_chain(&self, obj: &Object, symtab: &SymbolTable, chain: u32, name: &str) -> Option<Symbol> {
        let sym = Symbol(chain);
        match symtab.index(obj, sym) {
            FoundSymbol::Defined(sym_name, _) | FoundSymbol::Undefined(sym_name) =>
                if sym_name == name {
                    Some(sym)
                } else {
                    let next_chain = self.index_chain(obj, chain as usize);
                    self.follow_chain(obj, symtab, next_chain, name)
                }

            FoundSymbol::None =>
                None
        }
    }

    fn lookup(&self, obj: &Object, name: &str) -> Option<Symbol> {
        let symtab = obj.dynamic().symtab();
        let sym_hash = elf::hash::hash(name);
        let n_bucket = self.n_bucket(obj);
        let n_chain = self.n_chain(obj);

        let bucket = sym_hash % (n_bucket as u32);
        let chain = self.index_buckets(obj, bucket as usize);

        self.follow_chain(obj, &symtab, chain, name)
    }
}

enum FoundSymbol<'a> {
    Defined(&'a str, usize),
    Undefined(&'a str),
    None
}

#[derive(Copy, Clone, Debug)]
struct SymbolTable {
    offs: ElfOffs,
    len: u32
}

impl SymbolTable {
    fn index<'a>(&self, obj: &'a Object, sym: Symbol) -> FoundSymbol<'a> {
        let ElfOffs(symtab_offs) = self.offs;

        let sym_size = 16;
        let Symbol(sym_idx) = sym;
        if sym_idx >= self.len {
            // Out of bounds
            return FoundSymbol::None
        }

        let sym_offs = symtab_offs + sym_size * sym_idx;
        let sym_name_idx = obj.read32(sym_offs as usize);

        let elf = elf::ElfFile::new(&obj.buf.buf()).unwrap();
        if let Ok(s) = elf.get_dyn_string(sym_name_idx) {
            let sym_addr = obj.read32(sym_offs as usize + 4);
            let sym_section = obj.read32(sym_offs as usize + 12) >> 16;

            if sym_section != 0 {
                FoundSymbol::Defined(s, sym_addr as usize)
            } else {
                FoundSymbol::Undefined(s)
            }
        } else {
            FoundSymbol::None
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum RelEntTy {
    Rel,
    Rela,
}

#[derive(Copy, Clone, Debug)]
struct RelocationTable {
    offs: ElfOffs,
    size: usize,
    ty: RelEntTy
}

impl RelocationTable {
    fn relocate(&self, obj: &mut Object, rest: &mut Objects) {
        let relocation = |offs: usize, ty| match ty {
            | RelocType::Relative =>
                obj.reloc_offs + (obj.read32(offs) as usize),

            | RelocType::Abs32(sym)
            | RelocType::GlobDat(sym)
            | RelocType::JumpSlot(sym) =>
                obj.reloc_offs + (obj.resolve_symbol(rest, sym) as usize),

            | RelocType::TlsTpOffs(sym) =>
                obj.reloc_offs + (obj.resolve_symbol(rest, sym) as usize) - obj.tls_tp,

            | RelocType::IRelative => {
                println!("STUBBED: IRELATIVE relocation with IFUNC@{:X}", obj.read32(offs));
                0
            }
        };

        let ent_size = match self.ty {
            RelEntTy::Rel => 8,
            RelEntTy::Rela => 12,
        };
        let table_offs = self.offs.0 as usize;

        for ent in 0 .. self.size / ent_size {
            let ent_offs = table_offs + ent * ent_size;

            let offs = obj.read32(ent_offs) as usize;
            let info = obj.read32(ent_offs + 4);
            let ty = info as u8;
            let sym = Symbol(info >> 8);

            const R_ARM_ABS32: u8 = 2;
            const R_ARM_TLS_TPOFF32: u8 = 19;
            const R_ARM_GLOB_DAT: u8 = 21;
            const R_ARM_JUMP_SLOT: u8 = 22;
            const R_ARM_RELATIVE: u8 = 23;

            let ty = match ty {
                R_ARM_ABS32 => RelocType::Abs32(sym),
                R_ARM_JUMP_SLOT => RelocType::JumpSlot(sym),
                R_ARM_GLOB_DAT => RelocType::GlobDat(sym),
                R_ARM_RELATIVE => RelocType::Relative,
                R_ARM_TLS_TPOFF32 => RelocType::TlsTpOffs(sym),
                R_ARM_IRELATIVE => RelocType::IRelative,
                x => unimplemented!("relocation type {}", x),
            };

            let new_val = relocation(offs, ty);
            println!("STUBBED: Relocating val at {:X} from {:X} to {:X}",
                offs, obj.read32(offs), new_val);
        }
    }
}

enum RelocType {
    Relative,
    Abs32(Symbol),
    GlobDat(Symbol),
    JumpSlot(Symbol),
    TlsTpOffs(Symbol),
    IRelative,
}


#[repr(align(0x1000))]
#[derive(Copy, Clone)]
struct Page {
    _buf: [u8; 0x1000]
}

struct PageAlignedBuf {
    buf: Box<[Page]>
}
impl PageAlignedBuf {
    fn new(n_bytes: usize) -> Self {
        let pages = (n_bytes + 0xFFF) / 0x1000;
        let page_buf = vec![Page { _buf: [0; 0x1000] }; pages];
        PageAlignedBuf {
            buf: page_buf.into_boxed_slice()
        }
    }

    fn buf(&self) -> &[u8] {
        let ptr = self.buf.as_ptr() as *const u8;
        unsafe {
            slice::from_raw_parts(ptr, self.buf.len() * 0x1000)
        }
    }
    
    fn buf_mut(&mut self) -> &mut [u8] {
        let ptr = self.buf.as_mut_ptr() as *mut u8;
        unsafe {
            slice::from_raw_parts_mut(ptr, self.buf.len() * 0x1000)
        }
    }
}

fn read_bin(path: &str) -> PageAlignedBuf {
    let mut file = std::fs::File::open(path).unwrap();
    let size = file.metadata().unwrap().len() as usize;

    let mut buf = PageAlignedBuf::new(size);

    use std::io::Read;
    let read_amount = file.read(buf.buf_mut()).unwrap();
    assert!(read_amount == size);
    buf
}

struct Object {
    path: String,
    buf: PageAlignedBuf,
    dynamic: UnsafeCell<Option<Dynamic>>,
    reloc_offs: usize,
    tls_tp: usize,
}

impl Object {
    fn load_mem(path: &str) -> Self {
        println!("Loading `{}`", path);
        let buf = read_bin(path);

        let load_base = &buf.buf[0] as *const Page as usize;

        Self {
            path: path.to_owned(),
            buf: buf,
            dynamic: UnsafeCell::new(None),
            reloc_offs: load_base, // Assume elf base is 0 and all segments just work with load_base as an offset
            tls_tp: 0, // TODO: unimplemented
        }
    }

    fn dynamic(&self) -> &Dynamic {
        if let Some(ref dynamic) = unsafe { &*self.dynamic.get() } {
            dynamic
        } else {
            unsafe {
                *self.dynamic.get() = Some(Dynamic::new(self));
            }
            dbg!(self.dynamic())
        }
    }

    fn relocate(&mut self, rest: &mut Objects) {
        println!("Relocating `{}`...", self.path);
        if let Some(jmprel) = self.dynamic().jmprel {
            jmprel.relocate(self, rest);
        }
        if let Some(rel) = self.dynamic().rel {
            rel.relocate(self, rest);
        }
        if let Some(rela) = self.dynamic().rela {
            rela.relocate(self, rest);
        }
    }

    fn dependencies(&self) -> Vec<&str> {
        self.dynamic().deps.iter()
            .map(|dep| dep.to_str(self))
            .collect()
    }

    fn resolve_symbol_by_name(&self, others: &Objects, name: &str) -> usize {
        println!("STUBBED: Attempting to resolve symbol {}!", name);

        let hash_table = self.dynamic().hash();
        let symtab = self.dynamic().symtab();
        
        if let Some(found_sym) = hash_table.lookup(self, name) {
            match symtab.index(self, found_sym) {
                FoundSymbol::Defined(_, sym_addr) =>
                    return sym_addr + self.reloc_offs,

                _ => {}
            }
        }

        if let Objects::Cons(ref obj, ref rest) = others {
            obj.resolve_symbol_by_name(rest, name)
        } else {
            panic!("Could not find required symbol `{}`!", name);
        }
    }

    fn resolve_symbol(&self, others: &Objects, sym: Symbol) -> usize {
        let symtab = self.dynamic().symtab();
        match symtab.index(self, sym) {
            FoundSymbol::Defined(_, sym_addr) =>
                sym_addr + self.reloc_offs,

            FoundSymbol::Undefined(sym_name) =>
                self.resolve_symbol_by_name(others, sym_name),

            FoundSymbol::None =>
                panic!("Could not find required symbol `{:?}`!", sym)
        }
    }



    fn read32(&self, offs: usize) -> u32 {
        let convert32 = |sl: &[u8]| unsafe {
            *(sl.as_ptr() as *const u32)
        };

        let sl = &self.buf.buf()[offs..offs+4];
        convert32(sl)
    }
}

enum Objects {
    Cons(Object, Box<Objects>),
    End
}

impl Objects {
    fn load_mem_recursive_inner(obj: &Object) -> Box<Objects> {
        let mut head = Box::new(Objects::End);
        let deps = obj.dependencies();

        for dep in deps.iter() {
            let new = Object::load_mem(dep);
            head = Box::new(Objects::Cons(new, head));
        }

        let mut new_head = Box::new(Objects::End);
        {
            let mut tail = &mut *head;

            {
                let mut new_tail = &mut *new_head;

                for _dep in deps.iter() {
                    while let &mut Objects::Cons(_, ref mut rest) = new_tail {
                        new_tail = &mut *rest;
                    }

                    let (this_elf, rest) = if let &mut Objects::Cons(ref o, ref mut rest) = tail {
                        (o, rest)
                    } else {
                        unreachable!();
                    };

                    *new_tail = *Self::load_mem_recursive_inner(&this_elf);
                    tail = &mut *rest;
                }
            }
            *tail = *new_head;
        }

        head
    }

    fn load_mem_recursive(path: &str) -> Box<Self> {
        let this_elf = Object::load_mem(path);
        let list = Objects::Cons(this_elf, Box::new(Objects::End));
        let this_elf = if let Objects::Cons(o, _) = list {
            o
        } else {
            unreachable!();
        };

        Self::load_mem_recursive_inner(&this_elf)
    }

    fn relocate_all(&mut self) {
        // Here we need to relocate back to front
        
        let (obj, rest) = if let Self::Cons(ref mut obj, ref mut rest) = &mut *self {
            rest.relocate_all();
            (obj, rest)
        } else {
            return
        };

        obj.relocate(rest);
    }
}

pub struct Loader {

}

impl Loader {
    pub fn new() -> Self {
        Self { }
    }

    pub fn load_elf(&mut self, path: &str) {
        let mut objects = &mut *Objects::load_mem_recursive(path);

        objects.relocate_all();
    }
}

