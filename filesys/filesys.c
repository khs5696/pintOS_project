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
#include "threads/malloc.h"


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
	// 유섭인 do_format 안에 위치 (x)
	// persistance case 에서 -f가 없으면 안돼서 do_format에서는 추가 안 함
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
#ifdef EFILESYS
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
	/* 한양대 : 이 부분 변경 필요!
			  : root directory에만 생성하던 것을 'name' 경로에 
			  : '.', '..' 기능의 file 구현
			  : '/' 로 구분해서 절대, 상대 경로 기능 구현
			  : 'name' 원본을 보존해주기 위해(왜 해줘야하는 지는 모르겠음) 'name'을 다른 변수에 복사!
	*/
	// act_file_name은 몰라도 full_path_name은 제한 없어야 하는 거 아님?!?!?!?!??!?!?!
	char * full_path_name = (char *) malloc(strlen(name) + 1);
	char * act_file_name = (char *) malloc(sizeof(char)*(NAME_MAX+1));

	memcpy(full_path_name, name, strlen(name) + 1);

	struct dir * target_dir = parse_path(full_path_name, act_file_name);

// 새로운 file을 생성하기 위해 inode_disk가 만들어질 새로운 공간이 필요하므로,
// fat_create_chain(0) 호출 -> cluster를 리턴하기 때문에 sector로 변환
// inode_create에서 inode를 disk에 저장하고 initial_size가 포함되는 sector를 할당해 0으로 초기화

	bool success = (target_dir != NULL
			&& (inode_sector = cluster_to_sector(fat_create_chain(0)))
			&& inode_create (inode_sector, initial_size, true)
			&& dir_add (target_dir, act_file_name, inode_sector));
	if (!success && inode_sector != 0)
		fat_remove_chain(sector_to_cluster(inode_sector), 0);

	dir_close (target_dir);

	free(full_path_name);
	free(act_file_name);

	return success;
}
#else
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;

	struct dir *dir = dir_open_root ();
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size, true)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);

	dir_close (dir);

	return success;
}
#endif

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
#ifdef EFILESYS
struct file *
filesys_open (const char *name) {
	if(!strcmp(name, "/"))
		return dir_open_root();
	
	struct inode *inode = NULL;

	// act_file_name은 몰라도 full_path_name은 제한 없어야 하는 거 아님?!?!?!?!??!?!?!
	char * full_path_name = (char *) malloc(sizeof(char)*(NAME_MAX+1));
	char * act_file_name = (char *) malloc(sizeof(char)*(NAME_MAX+1));

	memcpy(full_path_name, name, strlen(name) + 1);

	struct dir * target_dir = parse_path(full_path_name, act_file_name);

	if (target_dir != NULL)
		dir_lookup (target_dir, act_file_name, &inode);
	dir_close (target_dir);

	free(full_path_name);
	free(act_file_name);

	return file_open (inode);
}
#else
struct file *
filesys_open (const char *name) {
	struct inode *inode = NULL;

	struct dir *dir = dir_open_root ();

	if (dir != NULL)
		dir_lookup (dir, name, &inode);
	dir_close (dir);

	return file_open (inode);
}
#endif

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
#ifdef EFILESYS
bool
filesys_remove (const char *name) {
	// act_file_name은 몰라도 full_path_name은 제한 없어야 하는 거 아님?!?!?!?!??!?!?!
	// 절대경로로 Root Directory를 지우려고 하는 경우
	if(!strcmp(name, "/"))
		return false;
	char * full_path_name = (char *) malloc(sizeof(char)*(NAME_MAX+1));
	char * act_file_name = (char *) malloc(sizeof(char)*(NAME_MAX+1));

	memcpy(full_path_name, name, strlen(name) + 1);

	struct dir * target_dir = parse_path(full_path_name, act_file_name);

	/*
		디렉터리엔트리에서file_name의in-memory inode가파일/디렉터리인지판단
		inode가디렉터리일경우디렉터리내파일존재여부검사
		디렉터리내파일이존재하지않을경우, 디렉터리에서file_name의엔트리삭제
		inode가파일일경우디렉터리엔트리에서file_name엔트리삭제
	*/
	// if (target_dir != NULL && sector_to_cluster(inode_get_inumber(dir_get_inode(target_dir))) == ROOT_DIR_CLUSTER) {
	// 	dir_close (target_dir);
	// 	free(full_path_name);
	// 	free(act_file_name);
	// 	return false;
	// }
	bool success = target_dir != NULL && dir_remove (target_dir, act_file_name);
	dir_close (target_dir);

	free(full_path_name);
	free(act_file_name);

	return success;
}
#else
bool
filesys_remove (const char *name) {
	struct dir *dir = dir_open_root ();
	bool success = dir != NULL && dir_remove (dir, name);
	dir_close (dir);

	return success;
}
#endif

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

	struct dir* curr_dir = dir_open (inode_open (cluster_to_sector (ROOT_DIR_CLUSTER)));
	dir_add (curr_dir, ".", inode_get_inumber(dir_get_inode(curr_dir)));
	dir_add (curr_dir, "..", inode_get_inumber(dir_get_inode(curr_dir)));
	dir_close(curr_dir);
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

// 함수 이름 바꿔야함!!!!!!!!!!!!!!!!
struct dir *
parse_path (char * path_name, char * file_name) {
	// 'path_name'을 분석해서 앞으로 작업을 진행할 directory를 리턴
	// 'file_name' : 'path_name'을 분석한 결과로 앞의 경로에 대한 정보를 제거하고 순수하게 만들
	// 			   : 것에 대한 이름을 저장
	// 'path_name'의 시작이 ‘/’의 여부에 따라 절대, 상대경로 구분하여 디렉토리 정보를 dir에 저장
	// strtok_r() 함수를 이용하여 'path_name'의 디렉토리 정보와 파일 이름 저장
	// 'file_name'에 파일 이름 저장
	// 'dir'로 오픈된 디렉토리를 포인팅
	struct dir* dir;
	// path_name과 file_name을 만들어 놓고 함수가 실행되어야 함.
	if (path_name == NULL || file_name == NULL)
		return NULL;
	if (strlen(path_name) == 0)
		return NULL;
	/* 'path_name'의 절대/상대 경로에 따른 디렉토리 정보 저장 */
	if (path_name[0] == '/') {
		dir = dir_open_root();
		path_name += 1;
	} else
		dir = dir_reopen(thread_current()->work_dir);

	// parsing을 진행하며 경로따라 목표 directory로 이동
	char* token;
	char* nextToken;
	char* savePtr;
	
	token = strtok_r(path_name, "/", &savePtr);
	nextToken = strtok_r(NULL, "/", &savePtr);
	struct inode * lookup_inode;

	while (token != NULL && nextToken != NULL) {
		/* dir에서 token이름의 파일을 검색하여 inode의 정보를 저장 */
		dir_lookup (dir, token, &lookup_inode);
		/* inode가 파일일 경우 NULL 반환 */
		if (!inode_is_dir(lookup_inode))
			return NULL;

		// dir_lookup을 했는데 해당 경로가 존재하지 않는 경우
		if(lookup_inode == NULL)
			return NULL;
		
		/* dir의 디렉토리 정보를 메모리에서 해지 */
		dir_close(dir);
		/* inode의 디렉토리 정보를 dir에 저장 */
		dir = dir_open(lookup_inode);
		/* token에 검색할 경로 이름 저장 */
		token = nextToken;
		nextToken = strtok_r(NULL, "/", &savePtr);
	}
	// 이상적인 상황은 token에 filename이고 nextToken이 NULL
	/* token의 파일 이름을 file_name에 저장 */
	int file_name_len = NAME_MAX > strlen(token) ? strlen(token) + 1 : NAME_MAX + 1;
	memcpy(file_name, token, file_name_len);
	/* dir 정보 반환 */
	return dir;
}


bool
filesys_create_dir (const char* name) {
	/* name 경로 분석 */
	// act_file_name은 몰라도 full_path_name은 제한 없어야 하는 거 아님?!?!?!?!??!?!?!
	char * full_path_name = (char *) malloc(sizeof(char)*(NAME_MAX+1));
	char * act_file_name = (char *) malloc(sizeof(char)*(NAME_MAX+1));

	memcpy(full_path_name, name, strlen(name) + 1);

	struct dir * target_dir = parse_path(full_path_name, act_file_name);

	// parse_path에서 해당 경로가 존재하지 않음.
	if (target_dir == NULL)
		return false;
	
	struct inode * final_inode;
	disk_sector_t inode_sector;
	dir_lookup (target_dir, act_file_name, &final_inode);
	bool success = false;
	// 이미 만들고자 하는 directory가 존재하는 경우
	if (final_inode == NULL) {
		// 실제 생성
		success = (target_dir != NULL
					&& (inode_sector = cluster_to_sector(fat_create_chain(0)))
					/* 할당받은 sector에 file_name의 디렉토리 생성 */
					// 할당받은 inode_sector에 directory용 inode 저장
					&& dir_create (inode_sector, 0)
					/* 디렉토리 엔트리에 file_name의 엔트리 추가 */
					&& dir_add (target_dir, act_file_name, inode_sector));
		if (!success && inode_sector != 0)
			fat_remove_chain(sector_to_cluster(inode_sector), 0);
		/* 디렉토리 엔트리에 ‘.’, ‘..’ 파일의 엔트리 추가 */

		struct dir* final_dir = dir_open(inode_open(inode_sector));
		dir_add(final_dir, ".", inode_sector);
		dir_add(final_dir, "..", inode_get_inumber(dir_get_inode(target_dir)));
		dir_close(final_dir);
	}
	
	dir_close(target_dir);
	return success;
}
