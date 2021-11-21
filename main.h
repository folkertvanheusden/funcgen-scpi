#include <mutex>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <vector>
#include <pipewire/pipewire.h>
#include <spa/param/audio/format-utils.h>

#define N_SNR 4

typedef enum { CM_AS_IS, CM_CLIP, CM_ATAN, CM_TANH, CM_DIV } clip_method_t;

typedef enum { S_SIN = 0, S_SQUARE, S_TRIANGLE } slot_type_t;

typedef struct {
	double freq, amp, offset;
	bool enabled;
	slot_type_t type;
} slot_t;

typedef struct
{
	std::string dev_name;
	unsigned int sample_rate, n_channels, bits;

	clip_method_t cm;

	std::thread *th;
        struct pw_main_loop *loop;
        struct pw_stream *stream;
	struct spa_pod_builder b;
        const struct spa_pod *params[1];
        uint8_t buffer[1024];
	struct spa_audio_info_raw saiw;
	struct pw_stream_events stream_events;

	std::mutex lock;
	std::vector<slot_t> freqs;
	int offset;

	int fd;  // client socket
} audio_dev_t;
