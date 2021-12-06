#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/fat.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* A directory. */
struct dir {
   struct inode *inode;                /* Backing store. */
   off_t pos;                          /* Current position.(readdir에서 사용) */
};

/* A single directory entry. */
struct dir_entry {
   disk_sector_t inode_sector;         /* Sector number of header. */
   char name[NAME_MAX + 1];            /* Null terminated file name. */
   bool in_use;                        /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
   // HS. inode_create 형태 변경 (is_file 추가)
   return inode_create(sector, entry_cnt * sizeof(struct dir_entry), false);
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode * inode) {
	struct dir * dir = calloc(1, sizeof * dir);
    if (inode != NULL && dir != NULL) {
		// HS. inode가 directory에 대한 inode인지
		ASSERT(inode_is_dir(inode))

    	dir->inode = inode;
        dir->pos = 0;
        return dir;
    } else {
        inode_close(inode);
        free(dir);
        return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root (void) {
#ifdef EFILESYS
   // HS. 클러스터 기준(ROOT_DIR_CLUSTER)으로 변환
   disk_sector_t root_sector = cluster_to_sector(ROOT_DIR_CLUSTER);
   struct inode * root_inode = inode_open(root_sector);
   return dir_open(root_inode);
#else
   return dir_open(inode_open (ROOT_DIR_SECTOR));
#endif
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir * dir) {
	return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir * dir) {
	if (dir != NULL) {
		inode_close(dir->inode);
		free(dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir * dir) {
   	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir * dir, const char * name,
		struct dir_entry * ep, off_t * ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (e.in_use && !strcmp(name, e.name)) {
			if (ep != NULL)
				* ep = e;
			if (ofsp != NULL)
				* ofsp = ofs;
			return true;
		}
	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir * dir, const char * name,
		struct inode ** inode) {
	struct dir_entry e;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (lookup(dir, name, &e, NULL))
		* inode = inode_open(e.inode_sector);
	else
		* inode = NULL;

	return * inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add (struct dir * dir, const char * name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Check NAME for validity. */
	if (* name == '\0' || strlen(name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup(dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy(e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir * dir, const char * name) {
	struct dir_entry e;
	struct inode * inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Find directory entry. */
	if (!lookup(dir, name, &e, &ofs))
		goto done;

	/* Open inode. */
	inode = inode_open(e.inode_sector);
		if (inode == NULL)
			goto done;

	// HS. 제거 대상이 directory인 경우
	if (inode_is_dir(inode)) {
		struct dir * target = NULL;
		struct dir_entry check_elem;
		bool is_empty = true;

		target = dir_open(inode);

		while (inode_read_at(target->inode, &check_elem, sizeof(check_elem), target->pos) == sizeof(check_elem)) {
			target->pos += sizeof(check_elem);
			if (check_elem.in_use)
				if (strcmp(check_elem.name, ".") && strcmp(check_elem.name, ".."))
				return false;
		}

		// directory 내부에 파일이나 폴더가 남아있다면? 실패
		// bool dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
		if (is_empty == false) {
			dir_close(target);
			return success;
		}

		// 제거하려는 directory가 현재 작업 중인 directory라면? 실패
		// directory는 동일한 inode일지라도 다른 메모리로 중복 할당될 수 있다.
		// => directory 주소가 아닌 실제 inode로 비교
		// (inode는 여러번 open 되더라도 open_cnt로 중복 카운트)
		struct dir * current_loc = thread_current()->work_dir;

		if (inode == dir_get_inode(current_loc)) {
			dir_close(target);
			return success;
		}

		// 제거하려는 directory의 inode가 여러번 오픈된 상태라면? 실패
		if (inode_open_cnt(inode) > 2) {
			dir_close(target);
			return success;
		}
	}
		
	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove(inode);
	success = true;

done:
	inode_close(inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir (struct dir * dir, char name[NAME_MAX + 1]) {
	struct dir_entry e;
	if (dir->pos == 0)
		dir->pos += sizeof(e) * 2;

	while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
		dir->pos += sizeof e;
		if (e.in_use) {
			// HS. directory entry가 '.', '..'인 경우 제외
			if (strcmp(e.name, ".") && strcmp(e.name, "..")) {
				strlcpy(name, e.name, NAME_MAX + 1);
				return true;
			}
		}
	}
	return false;
}

bool
dir_change (const char* dir) {
	bool result = false;
	// Root Directory로 이동하고자 하는 경우
	if (!strcmp(dir, "/")) {
		dir_close(thread_current()->work_dir);
		thread_current()->work_dir = dir_open_root();
		return true;
	}

	// parsing process : 경로 & 파일
	char * file_name = (char *) malloc(NAME_MAX+1);
	if (file_name == NULL)
		return false;
	struct dir * target_dir = search_target_dir(dir, file_name);
	
	// directory path가 유효한 경로인지 확인
	if (target_dir == NULL)
		goto clean;

	struct inode * lookup_inode;
	dir_lookup(target_dir, file_name, &lookup_inode);
	/* target_dir에서 최종적으로 이동하길 희망하는 directory가 없거나,
	 * directory가 아닌 file의 이름일 경우 */
	if (lookup_inode == NULL || !inode_is_dir(lookup_inode))
		goto close_inode;

	// 여기에도 soft link 고려해야하는 거 아님????

	// 현재 작업중인 directory(work_dir) 변경
	dir_close(thread_current()->work_dir);
	thread_current()->work_dir = dir_open(lookup_inode);
	result = true;
	goto clean;

close_inode:
	inode_close(lookup_inode);
clean:
	dir_close(target_dir);
	free(file_name);
	return result;
}

void
print_dir_entry (struct dir * dir) {
	struct dir_entry e;
	size_t ofs;

	printf("subdirectory list: \n");
	for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		printf("%s\n", e.name);
	return;
}