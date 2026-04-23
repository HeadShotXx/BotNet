SECTIONS
{
    .text : {
        *(.text.entry)
        *(.text)
        *(.text.payload)
    }
}
