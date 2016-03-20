#define offset(vaddr) vaddr & 0x00000fff
#define FIRST_TEN_BITS(vaddr) (vaddr & 0x003fffff) >> 22
#define SECOND_TEN_BITS(vaddr) (vaddr & 0xffc00fff) >> 12
PTE **first_layer_base = the virtual address of the first layer base
Output(int virtaddr, int length, ...) {
	List l = initialize a List<physaddr, physlength>

	//edge case
	if (virtaddr + length <= UP_TO_PAGE(virtaddr+1)) {
		l.append((v2p(virtaddr), length));
		give l to hardware
		return;
	}

	int first_page_boundary = UP_TO_PAGE(virtaddr);
	int last_page_boundary = DOWN_TO_PAGE(virtaddr + length);
	int cur_length = 0;
	int cur_start = virtaddr;
	int before = virtaddr;
	int after;
	for (after = first_page_boundary; after <= last_page_boundary; after += PAGESIZE) {
		cur_length += after - before;
		if (!contiguous(before, after)) {
			l.append((v2p(cur_start), cur_length));
			cur_length = 0;
			cur_start = after;
		}
		before = after;
	}
	cur_length += virtaddr + length - last_page_boundary;
	if (cur_length != 0) l.append((v2p(cur_start), cur_length));
	give l to hardware
	return;
}

//check if two virtual address in contiguous virtual pages are 
//also in contiguous physical pages
bool contiguous(int vaddr1, int vaddr2) {
	int paddr1 = getPTE(vaddr1);
	int paddr2 = getPTE(vaddr2);
	return (paddr1 >> PAGESHIFT) + 1 == (paddr2 >> PAGESHIFT) || 
		(paddr1 >> PAGESHIFT) == (paddr2 >> PAGESHIFT);
}

//find PTE to get physical address
int v2p(int vaddr) {
	PTE* second_layer = first_layer_base[FIRST_TEN_BITS(vaddr)];
	return (second_layer[SECOND_TEN_BITS(vaddr)].pfn<<PAGESHIFT) + offset(vaddr);
}