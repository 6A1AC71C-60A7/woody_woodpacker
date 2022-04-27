ENTRY(_start)

SECTIONS
{
	PROVIDE (__executable_start = SEGMENT_START("text-segment", 0x400000)); . = SEGMENT_START("text-segment", 0x400000) + SIZEOF_HEADERS;
	.text		:
	{
		*(.text.startup)
		*(.text*)
	}
}
