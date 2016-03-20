//This should be a part of the yalnix kernel
//The actual physical-to-virtual function is at the bottom.
//The name "vpn" used below spans across region boundary. 
//i.e. MEM_INVALID_PAGES <= vpn <= VMEM_SIZE >> PAGESHIFT
//For each region, this mechanism will take from one page to 2.5 pages
//memory, depending on how many v-to-p mappings exist.
//For each p-to-v lookup, the average time complexity is O(1). So are
//operations needed to maintain the underlying hashmap. 
#define VREGION_PAGE_NUM VMEM_REGION_SIZE >> PAGESHIFT
struct hashtable_entry{
	unsigned int pfn	: 20;
	unsigned int vpn    : 10;
	unsigned int unused :  2;
	struct hashtable_entry *next;
}
typedef struct pcb{
	...
	struct hashtable_entry **hashmap; //this map and all its entires should be freed when this process exits
} pcb;

pcb *current_process; //the currently running process, should be initialized and updated by kernel
struct hashtable_entry **kernel_hashmap; //initialized through build_hashmap below

//should be called after virtual memory is enabled and before any physical-to
//-virtual translation for kernel_hashmap and every newly created pcb.
void build_hashmap(struct hashtable_entry **hashtable) {
	hashtable = calloc(sizeof(struct hashtable_entry *) * VREGION_PAGE_NUM); //a page in size
	if (hashtable == NULL) {}//print calloc error
}

unsigned int hashcode(unsigned int key) {
	return key;
}

//should be called whenever a new virtual-to-physical mapping is added to page table
void hashmap_insert(int pfn, int vpn, struct hashtable_entry **hashtable) {
	int index = hashcode(pfn) % VREGION_PAGE_NUM;
	struct hashtable_entry *current = hashtable[index];
	struct hashtable_entry *prev = NULL;
	while (current != NULL) {
		prev = current;
		current = current->next;
	}
	current = calloc(sizeof(struct hashtable_entry));
	if (current == NULL) {}//print calloc error
	current->pfn = pfn;
	current->vpn = vpn;
	if (prev != NULL) prev->next = current;
}

//should be called whenever a virtual-to-physical mapping is deleted from page table
void hashmap_remove(int pfn, struct hashtable_entry **hashtable) {
	int index = hashcode(pfn) % VREGION_PAGE_NUM;
	struct hashtable_entry *current = hashtable[index];
	struct hashtable_entry *prev = NULL;
	while (current != NULL && current->pfn != pfn) {
		prev = current;
		current = current->next;
	}
	if (current == NULL) return;
	if (prev == NULL) hashtable[index] = current->next;
	else prev->next = current->next;
	free(current)
}

int hashmap_lookup(int pfn, struct hashtable_entry **hashtable) {
	int index = hashcode(pfn) % VREGION_PAGE_NUM;
	struct hashtable_entry *current = hashtable[index];
	while (current != NULL) {
		if (current->pfn == pfn) return current->vpn;
		current = current->next;
	}
	return -1;
}

unsigned int physical_to_virtual(unsigned int physical_addr) {
	int pfn = DOWN_TO_PAGE(physical_addr)>>PAGESHIFT;
	int vpn = hashmap_lookup(pfn, kernel_hashmap);
	if (vpn == -1) vpn = hashmap_lookup(pfn, current_process->hashmap);
	if (vpn == -1) return ERROR;
	return (vpn <<< PAGESHIFT) + (physical_addr & PAGEMASK);
}