#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot {
   unsigned int magic;
   unsigned int sectors_per_cluster; /* Fixed to 1 */
   unsigned int total_sectors; /* 할당한 전체 디스크의 크기를 sector 단위로 저장 */
   unsigned int fat_start; /* FAT가 시작하는 sector 위치 설정 */
   unsigned int fat_sectors; /* Size of FAT in sectors. */
   unsigned int root_dir_cluster; /* FAT 내에서 root directory의 위치 */
};

/* FAT FS */
struct fat_fs {
   struct fat_boot bs;
   unsigned int *fat;
   unsigned int fat_length;
   disk_sector_t data_start;
   cluster_t last_clst; /* 비어있는 cluster는 동일하게 linked-list형태로 연결. 그 list의 가장 앞 cluster */
   struct lock write_lock;
};

static struct fat_fs *fat_fs;

void fat_boot_create (void);
void fat_fs_init (void);

// 4-0-1 FAT init
// boot sector를 disk에서 읽어옴.
void
fat_init (void) {
   // 메모리에서 fat_fs 할당
   fat_fs = calloc (1, sizeof (struct fat_fs));
   if (fat_fs == NULL)
      PANIC ("FAT init failed");

   // Read boot sector from the disk (boot sector는 1 sector 크기니까)
   unsigned int *bounce = malloc (DISK_SECTOR_SIZE);
   if (bounce == NULL)
      PANIC ("FAT init failed");
   // FAT_BOOT_SECTOR(=0) sector의 내용을 filesys_disk에서 읽어서 bounce에 저장
   disk_read (filesys_disk, FAT_BOOT_SECTOR, bounce);
   memcpy (&fat_fs->bs, bounce, sizeof (fat_fs->bs));
   free (bounce);

   // Extract FAT info
   if (fat_fs->bs.magic != FAT_MAGIC)
      fat_boot_create ();
   fat_fs_init ();
}

// 4-0-7 do_format으로 FAT를 생성하였고, 이것을 open 해주는 역할.
void
fat_open (void) {
   fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
   if (fat_fs->fat == NULL)
      PANIC ("FAT load failed");

   // Load FAT directly from the disk
   uint8_t *buffer = (uint8_t *) fat_fs->fat;
   off_t bytes_read = 0;
   off_t bytes_left = sizeof (fat_fs->fat);
   const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
   for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
      bytes_left = fat_size_in_bytes - bytes_read;
      if (bytes_left >= DISK_SECTOR_SIZE) {
         disk_read (filesys_disk, fat_fs->bs.fat_start + i,
                    buffer + bytes_read);
         bytes_read += DISK_SECTOR_SIZE;
      } else {
         uint8_t *bounce = malloc (DISK_SECTOR_SIZE);
         if (bounce == NULL)
            PANIC ("FAT load failed");
         disk_read (filesys_disk, fat_fs->bs.fat_start + i, bounce);
         memcpy (buffer + bytes_read, bounce, bytes_left);
         bytes_read += bytes_left;
         free (bounce);
      }
   }
}

// 4-0-6 생성해준 FAT를 다시 닫음 -> 마지막에 disk에 저장하기 때문에, memory에서 생성한 FAT를 disk에 저장하는 역할도 함.
void
fat_close (void) {
   // Write FAT boot sector
   uint8_t *bounce = calloc (1, DISK_SECTOR_SIZE);
   if (bounce == NULL)
      PANIC ("FAT close failed");
   // fat_fs.bs의 내용을 bounce에 복사
   memcpy (bounce, &fat_fs->bs, sizeof (fat_fs->bs));
   // FAT_BOOT_SECTOR의 내용을 0으로 밀어버리는 역할
   disk_write (filesys_disk, FAT_BOOT_SECTOR, bounce);
   free (bounce);

   // Write FAT directly to the disk
   uint8_t *buffer = (uint8_t *) fat_fs->fat;
   off_t bytes_wrote = 0;
   off_t bytes_left = sizeof (fat_fs->fat);
   const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
   for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
      bytes_left = fat_size_in_bytes - bytes_wrote;
      if (bytes_left >= DISK_SECTOR_SIZE) {
         disk_write (filesys_disk, fat_fs->bs.fat_start + i,
                     buffer + bytes_wrote);
         bytes_wrote += DISK_SECTOR_SIZE;
      } else {
         bounce = calloc (1, DISK_SECTOR_SIZE);
         if (bounce == NULL)
            PANIC ("FAT close failed");
         memcpy (bounce, buffer + bytes_wrote, bytes_left);
         disk_write (filesys_disk, fat_fs->bs.fat_start + i, bounce);
         bytes_wrote += bytes_left;
         free (bounce);
         
      }
   }
}

// 4-0-5 값들을 바탕으로 FAT를 disk에 실제로 생성
void
fat_create (void) {
   // Create FAT boot
   fat_boot_create ();
   fat_fs_init ();

   // Create FAT table
   fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
   if (fat_fs->fat == NULL)
      PANIC ("FAT creation failed");

   // Set up ROOT_DIR_CLST
   // ROOT_DIR_CLUSTER(=1) 위치의 FAT 값을 EOChain으로 변경
   // root directory를 생성?
   fat_put (ROOT_DIR_CLUSTER, EOChain);

   for (int i = 3; i < fat_fs->fat_length; i++){
      fat_put(i-1, i);
   }

   fat_fs->last_clst = 2;

   // Fill up ROOT_DIR_CLUSTER region with 0
   uint8_t *buf = calloc (1, DISK_SECTOR_SIZE);
   if (buf == NULL)
      PANIC ("FAT create failed due to OOM");
   disk_write (filesys_disk, cluster_to_sector (ROOT_DIR_CLUSTER), buf);
   free (buf);
}

// 4-0-2 fat_fs.bs를 초기화
// 각 attribute의 의미는 위의 fat_boot에 설명
void
fat_boot_create (void) {
   unsigned int fat_sectors =
       (disk_size (filesys_disk) - 1)
       / (DISK_SECTOR_SIZE / sizeof (cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
   fat_fs->bs = (struct fat_boot){
       .magic = FAT_MAGIC,
       .sectors_per_cluster = SECTORS_PER_CLUSTER,
       .total_sectors = disk_size (filesys_disk),
       .fat_start = 1,
       .fat_sectors = fat_sectors,
       .root_dir_cluster = ROOT_DIR_CLUSTER,
   };
}

// 4-0-3 fat_fs를 init
void
fat_fs_init (void) {
   /* TODO: Your code goes here. */
   // fat_length : file system 안에 현재 사용할 수 있는 cluster의 수
   fat_fs->fat_length = (fat_fs->bs.total_sectors - 1 - fat_fs->bs.fat_sectors) / SECTORS_PER_CLUSTER;
   // data_start : 처음으로 file을 저장하기 시작할 수 있는 sector의 index
   fat_fs->data_start = fat_fs->bs.fat_sectors + fat_fs->bs.fat_start;
   lock_init(&fat_fs->write_lock);
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
 // Warning : 일단 fat_put에 lock관련이 있어서 추가 안했는데, create 시작과 끝에 lock 필요할 수도
cluster_t
fat_create_chain (cluster_t clst) {
   /* TODO: Your code goes here. */
   // last_clst가 FAT 영역을 벗어난 경우
   if(fat_fs->last_clst == 0 || fat_fs->last_clst >= fat_fs->fat_length)
      return 0;
   // last_clst : 비어 있는 어떤 cluster를 가리킴.
   cluster_t empty = fat_fs->last_clst;
   cluster_t next_empty = fat_get(empty);
   ASSERT(next_empty != 0);

   static char zeros[DISK_SECTOR_SIZE];
   // 새로운 chain 시작
   if (clst == 0) {
      fat_put(empty, EOChain);
      fat_fs->last_clst = next_empty;
      disk_write(filesys_disk, cluster_to_sector(empty), zeros);
      return empty;
   }
   cluster_t next_file_cluster = fat_get(clst);
   fat_put(clst, empty);
   fat_put(empty, next_file_cluster);
   fat_fs->last_clst = next_empty;
   disk_write(filesys_disk, cluster_to_sector(empty), zeros);
   return empty;
}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */
// pclst는 chain에서 바로 직전의 cluster
// 이 함수가 실행되고 나면, pclst는 업데이트된 chain의 가장 마지막 element가 되어야한다.
// 'clst'가 chain의 첫번째 element인 경우, pclst는 0이어야 한다.
void
fat_remove_chain (cluster_t clst, cluster_t pclst) {
   /* TODO: Your code goes here. */
   ASSERT (pclst == 0 || fat_get(pclst) == clst);
   if (pclst != 0)
      fat_put(pclst, EOChain);
   
   cluster_t last_chain_clst = clst;

   while (last_chain_clst != EOChain)
      last_chain_clst = fat_get(last_chain_clst);
   
   lock_acquire (&fat_fs->write_lock);
   fat_put(last_chain_clst, fat_fs->last_clst);
   fat_fs->last_clst = clst;
   lock_release (&fat_fs->write_lock);
}   

/* Update a value in the FAT table. */
// cluster number 'clst'로 표시된 FAT entry를 val로 업데이트한다. 
// FAT의 각 entry는 chain에서 그 다음 cluster를 가리키고 있기 때문에 (존재하는 경우; 아니라면 EOChain), 
// 이것은 연결성을 update하는 데 사용될 수 있다.
// fat_create에서 사용
void
fat_put (cluster_t clst, cluster_t val) {
   /* TODO: Your code goes here. */
   // clst 0은 Boot Sector용이라서 안 되고, clst가 FAT보다 큰 값이 들어오면 접근 불가!
   if (clst == 0 || clst >= fat_fs->fat_length)
      return;
   lock_acquire (&fat_fs->write_lock);
   fat_fs->fat[clst] = val;
   lock_release (&fat_fs->write_lock);
}

/* Fetch a value in the FAT table. */
// 주어진 cluster clst가 가리키고 있는 cluster number를 리턴
// 잘못된 clst가 주어진 경우 0을 리턴! (cluster_t는 uint니까 음수를 가질 수 없음)
cluster_t
fat_get (cluster_t clst) {
   /* TODO: Your code goes here. */
   if (clst == 0 || clst >= fat_fs->fat_length)
      return 0;
   return fat_fs->fat[clst];
}

/* Covert a cluster # to a sector number. */
// fat_create에서 사용
// 현재 FAT는 1번째 칸을 ROOT_DIRECTORY를 위한 칸으로 사용하고 있다.
// 그리고 fat_fs.data_start는 FAT 바로 뒤를 가리키고 있음으로,
// Directory와 File을 위한 sector 전부를 포함하는 공간이라고 생각할 수 있다.
// 따라서 FAT에서 n번째 cluster는 실제 disk에서 data_start + (n-1) 번째 sector와 같다고 할 수 있다.
disk_sector_t
cluster_to_sector (cluster_t clst) {
   /* TODO: Your code goes here. */
   // clst가 0이면 잘못된 clst (disk_sector_t는 uint임으로 음수를 가질 수 없음)
   if (clst == 0)
      return 0;
   return fat_fs->data_start + (clst - 1) * SECTORS_PER_CLUSTER;
}

cluster_t
sector_to_cluster (disk_sector_t sector) {
   return (sector - fat_fs->data_start) / SECTORS_PER_CLUSTER + 1;
}

/* 4-2-3 file의 길이는 1 sector로 제한되지 않는다. 따라서, 특정 file의
		 offset을 찾고자 할 때 file-chain을 탐색해야할 수도 있다. 특정
		 file의 시작 cluster와 file내에서 찾고 싶은 offset이 'pos'로 
		 주어질 때, file-chain내에서 pos가 위치한 sector를 리턴한다.
		 byte_to_sector에서 사용
*/
disk_sector_t
get_sector_using_fat (cluster_t start, off_t pos){
	off_t pos_left = pos % (DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER);
	off_t cluster_cnt = pos / (DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER);
	
	for(int i = 0; i < cluster_cnt; i++){
		start = fat_get(start);
		if(start == EOChain){
			PANIC("Can't go further");
		}
	}
	disk_sector_t sector = cluster_to_sector(start);
	sector += pos_left / DISK_SECTOR_SIZE;
	return sector;
}