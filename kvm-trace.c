#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "kvm/kvm-trace.h"
#include "kvm/kvm-cpu.h"

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <stdarg.h>

struct kvm_trace *kvm_trace__create(size_t capacity)
{
    	struct kvm_trace *trace;
    	size_t state_size;

    	if (capacity == 0) {
        	errno = EINVAL;
        	return NULL;
    	}

    	state_size = kvm_trace_arch__state_size();

    	if (state_size == 0) {
        	errno = EINVAL;
        	return NULL;
    	}

    	/* Evita overflow durante il calcolo delle dimensioni. */
    	if (capacity > SIZE_MAX / sizeof(*trace->entries) ||
        	capacity > SIZE_MAX / state_size) {
        	errno = EOVERFLOW;
        	return NULL;
    	}

    	trace = calloc(1, sizeof(*trace));
    	if (!trace)
        	return NULL;

    	trace->entries = calloc(capacity, sizeof(*trace->entries));
    	if (!trace->entries)
        	goto error;

    	trace->arch_states = calloc(capacity, state_size);
    	if (!trace->arch_states)
        	goto error;

    	trace->count = 0;
    	trace->capacity = capacity;
    	trace->arch_state_size = state_size;

    	/*
     	* Collega ogni entry alla propria porzione del buffer
     	* contenente gli stati specifici dell'architettura.
     	*/
    	for (size_t i = 0; i < capacity; i++) {
        	trace->entries[i].arch_state =
            		(struct kvm_trace_arch_state *)
            		((unsigned char *)trace->arch_states +
             		i * state_size);
    	}

    	return trace;

error:
    	free(trace->arch_states);
    	free(trace->entries);
    	free(trace);

    	return NULL;
}

int kvm_trace__record(struct kvm_trace *trace, struct kvm_cpu *vcpu)
{
    	struct kvm_trace_entry *entry;
    	int ret;

    	if (!trace || !vcpu)
        	return -EINVAL;

    	if (!trace->entries || !trace->arch_states ||
        	trace->arch_state_size == 0)
        	return -EINVAL;

    	/*
     	* Non scrivere oltre la capacità allocata.
     	*/
    	if (trace->count >= trace->capacity)
        	return -ENOSPC;

    	/*
     	* Recupera la prossima entry disponibile.
     	*/
    	entry = &trace->entries[trace->count];

    	/*
     	* Inizializza i dati dello step corrente.
     	* Il puntatore arch_state è già stato impostato
     	* da kvm_trace__create().
     	*/
    	entry->step = trace->count;
    	entry->pc = 0;

    	memset(entry->arch_state, 0, trace->arch_state_size);

    	/*
     	* Acquisisce il PC e lo stato architetturale.
     	*/
    	ret = kvm_trace_arch__capture(vcpu,
                                  &entry->pc,
                                  entry->arch_state);
    	if (ret < 0)
        	return ret;

    	/*
     	* Lo step viene considerato registrato soltanto
     	* dopo che la cattura è terminata correttamente.
     	*/
    	trace->count++;

    	return 0;
}


static int kvm_trace__ensure_test_dir(void)
{
    	struct stat st;

    	if (mkdir("Test", 0755) == 0)
        	return 0;

    	if (errno != EEXIST)
        	return -errno;

    	if (stat("Test", &st) < 0)
        	return -errno;

    	return S_ISDIR(st.st_mode) ? 0 : -ENOTDIR;
}


int kvm_trace__save(const struct kvm_trace *trace,
                    const char *path)
{
    	FILE *fp;
    	int ret = 0;

    	if (!trace || !path)
        	return -EINVAL;

    	if (!trace->entries ||
        	!trace->arch_states ||
        	trace->arch_state_size == 0 ||
        	trace->count > trace->capacity)
        	return -EINVAL;
	
	if (strncmp(path, "Test/", 5) == 0) {
    		ret = kvm_trace__ensure_test_dir();
    		if (ret < 0)
        	return ret;
	}

    	fp = fopen(path, "wb");
    	if (!fp)
        	return -errno;

    	/*
     	* Scrive il numero di entry valide.
     	*/
    	if (fwrite(&trace->count,
               	sizeof(trace->count), 1, fp) != 1) {
        	ret = -EIO;
        	goto out;
    	}

    	/*
     	* Scrive ciascuna entry:
     	* step -> pc -> stato architetturale.
     	*/
    	for (size_t i = 0; i < trace->count; i++) {
        	const struct kvm_trace_entry *entry =
            	&trace->entries[i];

        	if (!entry->arch_state) {
            	ret = -EINVAL;
            	goto out;
        	}

        	if (fwrite(&entry->step,
                   	sizeof(entry->step), 1, fp) != 1 ||
            	fwrite(&entry->pc,
                   	sizeof(entry->pc), 1, fp) != 1 ||
            	fwrite(entry->arch_state,
                   	trace->arch_state_size, 1, fp) != 1) {
            	ret = -EIO;
            	goto out;
        	}
    	}

out:
    	/*
     	* Controlla anche gli errori durante la chiusura.
     	*/
    	if (fclose(fp) != 0 && ret == 0)
        	ret = -EIO;

    	return ret;
}

struct kvm_trace *kvm_trace__load(const char *path)
{
    	FILE *fp;
    	struct kvm_trace *trace = NULL;
    	size_t count;
    	int saved_errno = 0;

    	if (!path) {
        	errno = EINVAL;
        	return NULL;
    	}

    	fp = fopen(path, "rb");
    	if (!fp)
        	return NULL;

    	/*
     	* Legge il numero di entry salvato da kvm_trace__save().
     	*/
    	if (fread(&count, sizeof(count), 1, fp) != 1) {
        	saved_errno = ferror(fp) ? EIO : EINVAL;
        	goto error;
    	}

    	/*
     	* Una traccia vuota non è accettata dalla versione
     	* corrente di kvm_trace__create().
     	*/
    	if (count == 0) {
        	saved_errno = EINVAL;
        	goto error;
    	}

    	/*
     	* Alloca gli array comuni e il buffer architetturale.
     	* I puntatori arch_state vengono inizializzati da create().
     	*/
    	trace = kvm_trace__create(count);
    	if (!trace) {
        	saved_errno = errno ? errno : ENOMEM;
        	goto error;
    	}

    	/*
     	* Ricostruisce tutte le entry.
     	*/
    	for (size_t i = 0; i < count; i++) {
        	struct kvm_trace_entry *entry = &trace->entries[i];

        	if (fread(&entry->step,
                  	sizeof(entry->step), 1, fp) != 1 ||
            	fread(&entry->pc,
                  	sizeof(entry->pc), 1, fp) != 1 ||
            	fread(entry->arch_state,
                  	trace->arch_state_size, 1, fp) != 1) {
            	saved_errno = ferror(fp) ? EIO : EINVAL;
            	goto error;
        	}

        	/*
         	* L'entry viene considerata valida solo dopo
         	* aver letto tutti i suoi campi.
         	*/
        	trace->count++;
    	}

    	if (fclose(fp) != 0) {
        	saved_errno = errno ? errno : EIO;
        	kvm_trace__free(trace);
        	errno = saved_errno;
        	return NULL;
    	}

    	return trace;

error:
    	fclose(fp);
    	kvm_trace__free(trace);
    	errno = saved_errno;
    	return NULL;
}

void kvm_trace__free(struct kvm_trace *trace)
{
    	if (!trace)
        	return;

    	free(trace->arch_states);
    	free(trace->entries);
    	free(trace);
}

const struct kvm_trace_entry *kvm_trace__get(const struct kvm_trace *trace, size_t index)
{
    	if (!trace || !trace->entries)
        	return NULL;

    	if (index >= trace->count)
        	return NULL;

    	return &trace->entries[index];
}

static bool has_bin_extension(const char *name)
{
    	size_t len;

    	if (!name)
        	return false;

    	len = strlen(name);

    	return len >= 4 && strcmp(name + len - 4, ".bin") == 0;
}

/*
 * Confronta due indirizzi PC per qsort().
 */
static int compare_pc(const void *a, const void *b)
{
    	uint64_t pc_a = *(const uint64_t *)a;
    	uint64_t pc_b = *(const uint64_t *)b;

    	return (pc_a > pc_b) - (pc_a < pc_b);
}

/*
 * Conta gli indirizzi PC distinti nella traccia.
 */
static int count_unique_pcs(const struct kvm_trace *trace,
                            size_t *unique_count)
{
    	uint64_t *pcs;

    	if (!trace || !unique_count)
        	return -EINVAL;

    	*unique_count = 0;

    	if (trace->count == 0)
        	return 0;

    	if (trace->count > SIZE_MAX / sizeof(*pcs))
        	return -EOVERFLOW;

    	pcs = malloc(trace->count * sizeof(*pcs));
    	if (!pcs)
        	return -ENOMEM;

    	for (size_t i = 0; i < trace->count; i++) {
        	const struct kvm_trace_entry *entry;

        	entry = kvm_trace__get(trace, i);
        	if (!entry) {
            	free(pcs);
            	return -EINVAL;
        	}

        	pcs[i] = entry->pc;
    	}

    	qsort(pcs, trace->count, sizeof(*pcs), compare_pc);

    	*unique_count = 1;

    	for (size_t i = 1; i < trace->count; i++) {
        	if (pcs[i] != pcs[i - 1])
            	(*unique_count)++;
    	}

    	free(pcs);
    	return 0;
}


struct kvm_trace_edge_pair {
    	uint64_t from;
    	uint64_t to;
};

struct kvm_trace_file_summary {
    	char *path;
    	size_t instructions;
    	size_t unique_instructions;
    	size_t unique_edges;
    	size_t pc_offset;
};

/* Ordina gli edge per PC iniziale e poi per PC finale. */
static int compare_trace_edges(const void *a, const void *b)
{
    	const struct kvm_trace_edge_pair *ea = a;
    	const struct kvm_trace_edge_pair *eb = b;

    	if (ea->from != eb->from)
        	return ea->from < eb->from ? -1 : 1;

    	if (ea->to != eb->to)
        	return ea->to < eb->to ? -1 : 1;

    	return 0;
}

/* Conta gli edge unici in un array gia' ordinato. */
static size_t count_sorted_unique_edges(
    	const struct kvm_trace_edge_pair *edges, size_t count)
{
    	size_t unique = 0;

    	for (size_t i = 0; i < count; i++) {
        	if (i == 0 ||
            		edges[i].from != edges[i - 1].from ||
            		edges[i].to != edges[i - 1].to)
            		unique++;
    	}

    	return unique;
}

/* Conta i PC unici in un array gia' ordinato. */
static size_t count_sorted_unique_pcs(const uint64_t *pcs,
                                      size_t count)
{
    	size_t unique = 0;

    	for (size_t i = 0; i < count; i++) {
        	if (i == 0 || pcs[i] != pcs[i - 1])
            		unique++;
    	}

    	return unique;
}

/*
 * Espande un array dinamico evitando overflow aritmetici.
 * In caso di errore, il buffer originale rimane valido.
 */
static void *grow_array(void *array, size_t item_size,
                        size_t *capacity, size_t needed)
{
    	size_t new_capacity;
    	void *new_array;

    	if (needed <= *capacity)
        	return array;

    	if (item_size == 0 || needed > SIZE_MAX / item_size) {
        	errno = EOVERFLOW;
        	return NULL;
    	}

    	new_capacity = *capacity ? *capacity : 16;

    	while (new_capacity < needed) {
        	if (new_capacity > SIZE_MAX / 2) {
            		new_capacity = needed;
            		break;
        	}

        	new_capacity *= 2;
    	}

    	if (new_capacity > SIZE_MAX / item_size) {
        	errno = EOVERFLOW;
        	return NULL;
    	}

    	new_array = realloc(array, new_capacity * item_size);
    	if (!new_array)
        	return NULL;

    	*capacity = new_capacity;
    	return new_array;
}

/* Ordina le trace per istruzioni decrescenti. */
static int compare_trace_summaries(const void *a, const void *b)
{
    	const struct kvm_trace_file_summary *ta = a;
    	const struct kvm_trace_file_summary *tb = b;

    	if (ta->instructions != tb->instructions)
        	return ta->instructions > tb->instructions ? -1 : 1;

    	if (ta->unique_instructions != tb->unique_instructions)
        	return ta->unique_instructions >
               	tb->unique_instructions ? -1 : 1;

    	if (ta->unique_edges != tb->unique_edges)
        	return ta->unique_edges > tb->unique_edges ? -1 : 1;

    	return strcmp(ta->path, tb->path);
}

/*
 * Confronta due path completi usando le sequenze di PC
 * conservate nell'array globale prima del suo ordinamento.
 */
static int compare_path_indices(
    	size_t ia, size_t ib,
    	const struct kvm_trace_file_summary *summaries,
    	const uint64_t *pcs)
{
    	const struct kvm_trace_file_summary *a = &summaries[ia];
    	const struct kvm_trace_file_summary *b = &summaries[ib];
    	size_t common = a->instructions < b->instructions ?
                    a->instructions : b->instructions;

    	for (size_t i = 0; i < common; i++) {
        	uint64_t pa = pcs[a->pc_offset + i];
        	uint64_t pb = pcs[b->pc_offset + i];

        	if (pa != pb)
            		return pa < pb ? -1 : 1;
    	}

    	if (a->instructions != b->instructions)
        	return a->instructions < b->instructions ? -1 : 1;

    	return 0;
}

/* Merge sort: ordinamento esatto senza hash dei path. */
static void sort_path_indices(
    	size_t *indices, size_t *tmp,
    	size_t begin, size_t end,
    	const struct kvm_trace_file_summary *summaries,
    	const uint64_t *pcs)
{
    	size_t mid, i, j, k;

    	if (end - begin < 2)
        	return;

    	mid = begin + (end - begin) / 2;

    	sort_path_indices(indices, tmp, begin, mid, summaries, pcs);
    	sort_path_indices(indices, tmp, mid, end, summaries, pcs);

    	i = begin;
    	j = mid;
    	k = begin;

    	while (i < mid && j < end) {
        	if (compare_path_indices(indices[i], indices[j],
                                 summaries, pcs) <= 0)
            		tmp[k++] = indices[i++];
        	else
            		tmp[k++] = indices[j++];
    	}

    	while (i < mid)
        	tmp[k++] = indices[i++];

    	while (j < end)
        	tmp[k++] = indices[j++];

    	memcpy(indices + begin, tmp + begin,
           	(end - begin) * sizeof(*indices));
}


static int kvm_trace__build_report_path(const char *dir_path,
                                        char **report_path)
{
    	const char *name = "trace_report.txt";
    	size_t dir_len, name_len, sep_len, path_len;
    	bool has_slash;
    	int n;

    	if (!dir_path || !*dir_path || !report_path)
        	return -EINVAL;

    	*report_path = NULL;

    	dir_len = strlen(dir_path);
    	name_len = strlen(name);
    	has_slash = dir_path[dir_len - 1] == '/';
    	sep_len = has_slash ? 0 : 1;

    	if (dir_len > SIZE_MAX - sep_len ||
        	dir_len + sep_len > SIZE_MAX - name_len - 1)
        	return -ENAMETOOLONG;

    	path_len = dir_len + sep_len + name_len + 1;

    	*report_path = malloc(path_len);
    	if (!*report_path)
        	return -ENOMEM;

    	n = snprintf(*report_path, path_len, "%s%s%s",
                 dir_path, has_slash ? "" : "/", name);

    	if (n < 0 || (size_t)n >= path_len) {
        	free(*report_path);
        	*report_path = NULL;
        	return -ENAMETOOLONG;
    	}

    	return 0;
}

static int kvm_trace__report_printf(FILE *report,
                                   const char *fmt, ...)
{
    	va_list ap, copy;
    	int console_ret, file_ret = 0;

    	va_start(ap, fmt);
    	va_copy(copy, ap);

    	console_ret = vprintf(fmt, ap);

    	if (report)
        	file_ret = vfprintf(report, fmt, copy);

    	va_end(copy);
    	va_end(ap);

    	if (console_ret < 0 || (report && file_ret < 0))
        	return -EIO;

    	return 0;
}


int kvm_trace__analyze_dir(const char *dir_path)
{
    	FILE *report = NULL;
	char *report_path = NULL;
	int report_error = 0;
	
	DIR *dir;
    	struct dirent *entry;
    	struct kvm_trace_file_summary *summaries = NULL;
    	uint64_t *all_pcs = NULL;
    	struct kvm_trace_edge_pair *all_edges = NULL;
    	size_t *path_order = NULL;
    	size_t *path_tmp = NULL;

    	size_t summary_count = 0, summary_capacity = 0;
    	size_t pc_count = 0, pc_capacity = 0;
    	size_t edge_count = 0, edge_capacity = 0;

    	size_t files_found = 0, errors = 0;
    	size_t global_unique_pcs = 0;
    	size_t global_unique_edges = 0;
    	size_t unique_paths = 0;

    	int dir_error = 0;
    	int path_error = 0;

    	if (!dir_path)
        	return -EINVAL;

    	dir = opendir(dir_path);
    	if (!dir)
        	return -errno;

    	while (1) {
        	char *path;
        	size_t dir_len, name_len, path_len;
        	size_t unique_pcs, unique_edges;
        	size_t added_edges;
        	size_t pc_offset, edge_offset;
        	bool has_slash;
        	struct stat st;
        	struct kvm_trace *trace;
        	struct kvm_trace_file_summary *new_summaries;
        	uint64_t *new_pcs;
        	struct kvm_trace_edge_pair *new_edges;
        	int ret;

        	errno = 0;
        	entry = readdir(dir);

        	if (!entry) {
            		if (errno)
                		dir_error = -errno;
            		break;
        	}

        	if (strcmp(entry->d_name, ".") == 0 ||
            		strcmp(entry->d_name, "..") == 0)
            		continue;

        	if (!has_bin_extension(entry->d_name))
            		continue;

        	dir_len = strlen(dir_path);
        	name_len = strlen(entry->d_name);
        	has_slash = dir_len > 0 &&
                    dir_path[dir_len - 1] == '/';

        	if (name_len > SIZE_MAX - (has_slash ? 1 : 2) ||
            		dir_len > SIZE_MAX - name_len -
                      	(has_slash ? 1 : 2)) {
            		fprintf(stderr, "Path too long: %s\n",
                    		entry->d_name);
            		errors++;
            		continue;
        	}

        	path_len = dir_len + name_len +
                   	(has_slash ? 1 : 2);

        	path = malloc(path_len);
        	if (!path) {
            		fprintf(stderr, "Out of memory\n");
            		errors++;
            		continue;
        	}

        	if (has_slash)
            		snprintf(path, path_len, "%s%s",
                     		dir_path, entry->d_name);
        	else
            		snprintf(path, path_len, "%s/%s",
                     		dir_path, entry->d_name);

        	if (stat(path, &st) < 0) {
            		fprintf(stderr, "Cannot stat %s: %s\n",
                    		path, strerror(errno));
            		free(path);
            		errors++;
            		continue;
        	}

        	if (!S_ISREG(st.st_mode)) {
            		free(path);
            		continue;
        	}

        	files_found++;

        	trace = kvm_trace__load(path);
        	if (!trace) {
            		fprintf(stderr, "Cannot load trace: %s\n", path);
            		free(path);
            		errors++;
            		continue;
        	}

        	ret = count_unique_pcs(trace, &unique_pcs);
        	if (ret < 0) {
            		fprintf(stderr, "Cannot count unique PCs in %s: %d\n",
                    	path, ret);
            		kvm_trace__free(trace);
            		free(path);
            		errors++;
            		continue;
        	}

        	added_edges = trace->count > 0 ?
                      	trace->count - 1 : 0;

        	if (summary_count == SIZE_MAX ||
            		trace->count > SIZE_MAX - pc_count ||
            		added_edges > SIZE_MAX - edge_count) {
            		fprintf(stderr, "Trace statistics overflow: %s\n",
                    		path);
            		kvm_trace__free(trace);
            		free(path);
            		errors++;
            		continue;
        	}

        	/*
         	* Riserva tutti i buffer prima di aggiungere i dati.
         	* In caso di errore, i contatori globali rimangono invariati.
         	*/
        	new_summaries = grow_array(
            		summaries, sizeof(*summaries), &summary_capacity,
            		summary_count + 1);
        	if (!new_summaries) {
            		fprintf(stderr, "Cannot allocate trace summaries\n");
            		kvm_trace__free(trace);
            		free(path);
            		errors++;
            		continue;
        	}
        	summaries = new_summaries;

        	new_pcs = grow_array(
            		all_pcs, sizeof(*all_pcs), &pc_capacity,
            		pc_count + trace->count);
        	if (!new_pcs) {
            		fprintf(stderr, "Cannot allocate global PC data\n");
            		kvm_trace__free(trace);
            		free(path);
            		errors++;
            		continue;
        	}
        	all_pcs = new_pcs;

        	if (added_edges > 0) {
            		new_edges = grow_array(
                		all_edges, sizeof(*all_edges), &edge_capacity,
                		edge_count + added_edges);
            		if (!new_edges) {
                		fprintf(stderr, "Cannot allocate global edge data\n");
                		kvm_trace__free(trace);
                		free(path);
                		errors++;
                		continue;
            		}
            	all_edges = new_edges;
        	}

        	pc_offset = pc_count;
        	edge_offset = edge_count;

        	/* Conserva la sequenza originale per l'analisi dei path. */
        	for (size_t i = 0; i < trace->count; i++)
            		all_pcs[pc_offset + i] = trace->entries[i].pc;

        	/*
         	* Ogni edge e' una coppia direzionale di PC consecutivi.
         	* Non si creano mai edge tra file differenti.
         	*/
        	for (size_t i = 1; i < trace->count; i++) {
            		all_edges[edge_offset + i - 1].from =
                		trace->entries[i - 1].pc;
            		all_edges[edge_offset + i - 1].to =
                		trace->entries[i].pc;
        	}

        	/*
         	* Ordina soltanto il segmento degli edge di questo file
         	* per contarne gli edge unici. La sequenza di PC rimane
         	* intatta nell'array all_pcs.
         	*/
        	if (added_edges > 1) {
            		qsort(all_edges + edge_offset, added_edges,
                  		sizeof(*all_edges), compare_trace_edges);
        	}

        	unique_edges = count_sorted_unique_edges(
            		added_edges ? all_edges + edge_offset : NULL,
            		added_edges);

        	summaries[summary_count].path = path;
        	summaries[summary_count].instructions = trace->count;
        	summaries[summary_count].unique_instructions = unique_pcs;
        	summaries[summary_count].unique_edges = unique_edges;
        	summaries[summary_count].pc_offset = pc_offset;

        	summary_count++;
        	pc_count += trace->count;
        	edge_count += added_edges;

        	kvm_trace__free(trace);
    	}

    	if (closedir(dir) < 0 && !dir_error)
        	dir_error = -errno;
	
	report_error = kvm_trace__build_report_path(dir_path,
                                             &report_path);

	if (report_error == 0) {
    		report = fopen(report_path, "w");

    		if (!report) {
        		report_error = -errno;
        		pr_err("Cannot create report '%s': %s\n",
               			report_path, strerror(errno));
    		}
	} else {
    		pr_err("Cannot build report path: %s\n",
           	strerror(-report_error));
	}

    	/*
     	* Calcola i path globalmente unici confrontando le sequenze
     	* complete di PC, prima di ordinare all_pcs per il conteggio
     	* degli indirizzi globalmente unici.
     	*/
    	if (summary_count > 0) {
        	if (summary_count > SIZE_MAX / sizeof(*path_order)) {
            		path_error = -EOVERFLOW;
        	} else {
            		path_order = malloc(summary_count *
                                 sizeof(*path_order));
            		path_tmp = malloc(summary_count *
                              sizeof(*path_tmp));

            		if (!path_order || !path_tmp) {
                		path_error = -ENOMEM;
            		} else {
                		for (size_t i = 0; i < summary_count; i++)
                    			path_order[i] = i;

                		sort_path_indices(path_order, path_tmp,
                                  	0, summary_count,
                                  	summaries, all_pcs);

                		for (size_t i = 0; i < summary_count; i++) {
                    			if (i == 0 ||
                        			compare_path_indices(
                            				path_order[i - 1], path_order[i],
                            				summaries, all_pcs) != 0)
                        			unique_paths++;
                		}
            		}
        	}

        	if (path_error) {
            		fprintf(stderr,
                    		"Cannot calculate global path coverage: %s\n",
                    		strerror(-path_error));
            		errors++;
        	}
    	}

    	free(path_order);
    	free(path_tmp);

    	/*
     	* Calcola gli insiemi globali di PC ed edge unici.
     	*/
    	if (pc_count > 1)
        	qsort(all_pcs, pc_count, sizeof(*all_pcs), compare_pc);

    	global_unique_pcs = count_sorted_unique_pcs(all_pcs, pc_count);

    	if (edge_count > 1) {
        	qsort(all_edges, edge_count, sizeof(*all_edges),
              		compare_trace_edges);
    	}

    	global_unique_edges = count_sorted_unique_edges(all_edges,
                                                    edge_count);

    	/*
     	* Classifica i file per numero di istruzioni decrescente.
     	*/
    	if (summary_count > 1) {
        	qsort(summaries, summary_count, sizeof(*summaries),
              		compare_trace_summaries);
    	}

    	kvm_trace__report_printf("\nTrace ranking (instructions descending)\n\n");
    	kvm_trace__report_printf("%-5s %-40s %12s %14s %14s\n",
           	"Rank", "Trace", "Instructions",
           	"Unique PCs", "Unique edges");

    	for (size_t i = 0; i < summary_count; i++) {
        	kvm_trace__report_printf("%-5zu %-40s %12zu %14zu %14zu\n",
               	i + 1,
               	summaries[i].path,
               	summaries[i].instructions,
               	summaries[i].unique_instructions,
               	summaries[i].unique_edges);
    	}

    	kvm_trace__report_printf("\nGlobal coverage summary\n\n");
    	kvm_trace__report_printf("Valid traces:                   %zu\n", summary_count);
    	kvm_trace__report_printf("Invalid or failed traces:       %zu\n", errors);
    	kvm_trace__report_printf("Total instruction observations: %zu\n", pc_count);
    	kvm_trace__report_printf("Globally unique instruction PCs: %zu\n",
           global_unique_pcs);
    	kvm_trace__report_printf("Total edge observations:        %zu\n", edge_count);
    	kvm_trace__report_printf("Globally unique directed edges: %zu\n",
           global_unique_edges);

    	if (!path_error) {
        	kvm_trace__report_printf("Distinct complete PC paths:     %zu / %zu traces\n",
               	unique_paths, summary_count);
    	} else {
        	kvm_trace__report_printf("Distinct complete PC paths:     unavailable\n");
    	}

    	kvm_trace__report_printf("\nPath definition: exact ordered PC sequence per file.\n");
    	kvm_trace__report_printf("Edge definition: directed pair of consecutive PCs.\n");
	

	if (report) {
    		if (fflush(report) == EOF && report_error == 0)
        		report_error = -(errno ? errno : EIO);

    		if (ferror(report) && report_error == 0)
        		report_error = -EIO;

    		if (fclose(report) == EOF && report_error == 0)
        		report_error = -(errno ? errno : EIO);

    		report = NULL;
	}

	if (report_error == 0)
    		pr_info("Trace report saved to '%s'\n", report_path);

	free(report_path);


    	for (size_t i = 0; i < summary_count; i++)
        	free(summaries[i].path);

    	free(summaries);
    	free(all_pcs);
    	free(all_edges);

    	if (dir_error)
        	return dir_error;

	if (report_error)
    		return report_error;

	return errors ? -EIO : 0;

}


bool kvm_trace__detect_cycle(struct kvm_trace *trace,
                             size_t max_period,
                             size_t min_repetitions)
{
    	size_t max_candidate;

    	if (!trace || !trace->entries ||
        	max_period == 0 || min_repetitions < 2)
        	return false;

    	/* Se il ciclo è già stato rilevato, non sovrascrivere i dati. */
    	if (trace->has_cycle)
        	return true;

    	/* Non abbiamo ancora abbastanza entry. */
    	if (trace->count / min_repetitions == 0)
        	return false;

    	max_candidate = trace->count / min_repetitions;

    	if (max_candidate > max_period)
        	max_candidate = max_period;

    	/*
     	* Prova periodi di lunghezza crescente.
     	* Il primo ciclo trovato è quello più corto tra
     	* quelli verificati.
     	*/
    	for (size_t period = 1;
        	 period <= max_candidate;
         	period++) {
        	size_t start =
            	trace->count - min_repetitions * period;
        	bool repeated = true;

        	/*
         	* Confronta ogni blocco con la prima occorrenza.
         	*/
        	for (size_t r = 1;
             	r < min_repetitions && repeated;
             	r++) {
            		for (size_t j = 0; j < period; j++) {
                		size_t first = start + j;
                		size_t current = start + r * period + j;

                		if (trace->entries[first].pc !=
                    		trace->entries[current].pc) {
                    			repeated = false;
                    			break;
                		}
            		}
        	}

        	if (repeated) {
            		trace->has_cycle = true;
            		trace->cycle_start = start;
            		trace->cycle_length = period;
            		trace->cycle_repetitions = min_repetitions;

            		return true;
        	}
    	}

    	return false;
}
