#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/fat.h"
#include "devices/disk.h"
#include "threads/thread.h"


/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");
	// inode_init : 그냥 list init해주는 게 전부
	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
	/* 한양대 : 현재 작업중인 directory를 나타내는 property에 root directry로 설정 
			  : dir_open_root()
	*/
	// 유섭인 do_format 안에 위치
	thread_current()->work_dir = dir_open_root();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
 // 4-2-0 create syscall에서 사용되던 filesys_create 수정
 /* 4-4-2 파일 혹은 디렉토리 생성시 사용
		  현재 dir는 무조건 root directory -> root direct
		  ory만 생성하겠다는 뜻 -> 이걸 바꿔야함!
*/
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
	/* 한양대 : 이 부분 변경 필요!
			  : '.', '..' 기능의 file 구현
			  : '/' 로 구분해서 절대, 상대 경로 기능 구현
	*/
	struct dir *dir = dir_open_root ();
#ifdef EFILESYS
// 새로운 file을 생성하기 위해 inode_disk가 만들어질 새로운 공간이 필요하므로,
// fat_create_chain(0) 호출 -> cluster를 리턴하기 때문에 sector로 변환
// inode_create에서 inode를 disk에 저장하고 initial_size가 포함되는 sector를 할당해 0으로 초기화

	bool success = (dir != NULL
			&& (inode_sector = cluster_to_sector(fat_create_chain(0)))
			&& inode_create (inode_sector, initial_size, true)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		fat_remove_chain(sector_to_cluster(inode_sector), 0);
#else
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size, true)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
#endif
	dir_close (dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	struct dir *dir = dir_open_root ();
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, name, &inode);
	dir_close (dir);

	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	struct dir *dir = dir_open_root ();
	bool success = dir != NULL && dir_remove (dir, name);
	dir_close (dir);

	return success;
}
/* 4-0-4 할당해주고 생성을 위한 값들을 이전에 설정해줬음으로, 그 값들을 바탕으로 FAT 생성 */
/* 4-2-1 free_map과 관련된 함수 모두 수정
		 root directory의 위치는 더이상 disk 상에서 sector 1에 위치하지 않는다. cluster 상에
		 서 1에 위치한 root directory의 위치를 sector로 변환하여 생성해야한다.
*/
/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	// 4-4-1 root directory를 실제로 생성
	if (!dir_create (cluster_to_sector(ROOT_DIR_CLUSTER), 2))
		PANIC ("root directory creation failed");
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
