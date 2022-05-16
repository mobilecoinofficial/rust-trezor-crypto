
// ed25519-donna base header
#include "ed25519.h"

// Test data via `ed25519-donna/test.c` and `ed25519-donna/regression.h`
typedef struct  {
	unsigned char sk[32], pk[32], sig[64];
	const char *m;
} test_data_t;

test_data_t test_dataset[] = {
#include "regression.h"
};
