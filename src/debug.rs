use anyhow::Result;
use gimli::Reader as _;
use object::{Object, ObjectSection, ObjectSegment};

use std::collections::HashMap;
use std::path::PathBuf;
use std::{borrow, fs};

#[derive(Debug)]
pub struct Dwarf {
    /// Function name and its range
    /// The range is a tuple of (start, end)
    function_range: HashMap<String, (u64, u64)>,
    /// Line number and its range
    /// The range is a tuple of (address, line, column)
    line_range: Vec<(PathBuf, (u64, u64, u64))>,
    // Stack trace
    // stacks: HashMap<u64, Vec<u64>>,
    inline_height: usize,
}

impl Dwarf {
    pub fn new(path: &PathBuf) -> Result<Self> {
        let file = fs::File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
        let object = object::File::parse(&*mmap)?;
        let load_bias = object
            .segments()
            .filter(|seg| seg.address() != 0)
            .map(|seg| seg.address() as i64 - seg.file_range().0 as i64)
            .min()
            .unwrap_or(0);
        assert_eq!(load_bias, 0); // ?
        let dwarf_sections = gimli::DwarfSections::load(|id| load_section(&object, id.name()))?;
        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let dwarf = dwarf_sections.borrow(|section| borrow_section(section, endian));

        let mut function_range = HashMap::new();
        let mut line_range = Vec::new();
        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            let unit_ref = unit.unit_ref(&dwarf);
            parse_info(unit_ref, &mut function_range, &mut line_range)?;
        }
        Ok(Dwarf {
            function_range,
            line_range,
            inline_height: 0,
        })
    }

    // pub fn reset_inline_height(&mut self) {
    //     self.inline_height = 0;
    // }

    pub fn inline_height(&mut self) -> usize {
        self.inline_height
    }

    // pub fn inline_stack_at_address(&self, _address: u64) -> Option<&Vec<u64>> {
    //     todo!()
    // }

    pub fn resolve_symbol(&self, symbol: &str) -> Option<(u64, u64)> {
        self.function_range.get(symbol).cloned()
    }

    pub fn simulate_inlined_step_in(&mut self) {
        self.inline_height -= 1;
    }

    pub fn line_range_at_address(&self, address: u64) -> Vec<&(PathBuf, (u64, u64, u64))> {
        let line = self
            .line_range
            .iter()
            .find(|(_, (addr, _, _))| *addr == address)
            .map(|(_, (_, line, _))| line);
        match line {
            Some(need_line) => self
                .line_range
                .iter()
                .filter(|(_, (_, line, _))| *line == *need_line)
                .collect(),
            None => Vec::new(),
        }
    }
}

fn parse_info(
    unit: gimli::UnitRef<Reader>,
    function_range: &mut HashMap<String, (u64, u64)>,
    line_range: &mut Vec<(PathBuf, (u64, u64, u64))>,
) -> Result<()> {
    function_addresses(unit, function_range)?;
    line_parser(unit, line_range)?;
    Ok(())
}

#[derive(Debug, Default)]
struct RelocationMap(object::read::RelocationMap);

impl gimli::read::Relocate for &RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

// The section data that will be stored in `DwarfSections` and `DwarfPackageSections`.
#[derive(Default)]
struct Section<'data> {
    data: borrow::Cow<'data, [u8]>,
    relocations: RelocationMap,
}

// The reader type that will be stored in `Dwarf` and `DwarfPackage`.
// If you don't need relocations, you can use `gimli::EndianSlice` directly.
type Reader<'data> =
    gimli::RelocateReader<gimli::EndianSlice<'data, gimli::RunTimeEndian>, &'data RelocationMap>;

// Load a `Section` that may own its data.
fn load_section<'data>(object: &object::File<'data>, name: &str) -> Result<Section<'data>> {
    Ok(match object.section_by_name(name) {
        Some(section) => Section {
            data: section.uncompressed_data()?,
            relocations: section.relocation_map().map(RelocationMap)?,
        },
        None => Default::default(),
    })
}

// Borrow a `Section` to create a `Reader`.
fn borrow_section<'data>(
    section: &'data Section<'data>,
    endian: gimli::RunTimeEndian,
) -> Reader<'data> {
    let slice = gimli::EndianSlice::new(borrow::Cow::as_ref(&section.data), endian);
    gimli::RelocateReader::new(slice, &section.relocations)
}

fn function_addresses(
    unit: gimli::UnitRef<Reader>,
    function_range: &mut HashMap<String, (u64, u64)>,
) -> Result<()> {
    let mut entries = unit.entries();
    while let Some((_, entry)) = entries.next_dfs()? {
        if entry.tag() == gimli::DW_TAG_subprogram {
            let mut attrs = entry.attrs();
            let mut name = None;
            while let Some(attr) = attrs.next()? {
                if attr.name() == gimli::DW_AT_name {
                    if let Ok(n) = unit.attr_string(attr.value()) {
                        let function_name = n.to_string_lossy()?.to_string();
                        name = Some(function_name);
                        function_range.insert(name.clone().unwrap(), (0, 0));
                    }
                } else if attr.name() == gimli::DW_AT_low_pc {
                    if let Ok(low_pc) = unit.attr_address(attr.value()) {
                        if let Some(name) = &name {
                            function_range
                                .entry(name.clone())
                                .and_modify(|v| v.0 = low_pc.unwrap_or_default());
                        }
                    }
                } else if attr.name() == gimli::DW_AT_high_pc {
                    if let gimli::AttributeValue::Udata(offset) = attr.value() {
                        if let Some(name) = &name {
                            function_range
                                .entry(name.clone())
                                .and_modify(|v| v.1 = offset + v.0);
                        }
                    }
                } else if attr.name() == gimli::DW_AT_ranges {
                    todo!()
                }
            }
        } else if entry.tag() == gimli::DW_TAG_inlined_subroutine {
            let mut attrs = entry.attrs();
            // DW_AT_abstract_origin: UnitRef(UnitOffset(847))
            // DW_AT_low_pc: Addr(4505)
            // DW_AT_high_pc: Udata(15)
            // DW_AT_call_file: FileIndex(1)
            // DW_AT_call_line: Udata(7)
            // DW_AT_call_column: Udata(3)
            // DW_AT_abstract_origin: UnitRef(UnitOffset(854))
            while let Some(_attr) = attrs.next()? {
                // println!("{}: {:?}", attr.name(), attr.value());
            }
        }
    }
    Ok(())
}

fn line_parser(
    unit: gimli::UnitRef<Reader>,
    line_range: &mut Vec<(PathBuf, (u64, u64, u64))>,
) -> Result<()> {
    if let Some(program) = unit.line_program.clone() {
        let comp_dir = if let Some(ref dir) = unit.comp_dir {
            PathBuf::from(dir.to_string_lossy()?.to_string())
        } else {
            PathBuf::new()
        };
        // Iterate over the line program rows.
        let mut rows = program.rows();
        while let Some((header, row)) = rows.next_row()? {
            if row.end_sequence() {
                // println!("{:x} end-sequence", row.address());
            } else {
                let mut path = PathBuf::new();
                if let Some(file) = row.file(header) {
                    path.clone_from(&comp_dir);
                    // The directory index 0 is defined to correspond to the compilation unit directory.
                    if file.directory_index() != 0 {
                        if let Some(dir) = file.directory(header) {
                            path.push(unit.attr_string(dir)?.to_string_lossy()?.as_ref());
                        }
                    }
                    path.push(
                        unit.attr_string(file.path_name())?
                            .to_string_lossy()?
                            .as_ref(),
                    );
                }
                // Determine line/column. DWARF line/column is never 0, so we use that
                // but other applications may want to display this differently.
                let line = match row.line() {
                    Some(line) => line.get(),
                    None => 0,
                };
                let column = match row.column() {
                    gimli::ColumnType::LeftEdge => 0,
                    gimli::ColumnType::Column(column) => column.get(),
                };
                line_range.push((path.clone(), (row.address(), line, column)));
            }
        }
        Ok(())
    } else {
        Err(anyhow::anyhow!("No line program found"))
    }
}
