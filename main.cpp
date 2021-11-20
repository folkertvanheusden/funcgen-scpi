#include <atomic>
#include <errno.h>
#include <libgen.h>
#include <limits>
#include <math.h>
#include <map>
#include <mutex>
#include <ncurses.h>
#include <signal.h>
#include <sndfile.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <pipewire/pipewire.h>
#include <spa/param/audio/format-utils.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/timeval.h>

#include <scpi/scpi.h>

#include "error.h"
#include "utils.h"
#include "main.h"

#define SCPI_INPUT_BUFFER_LENGTH 256
char scpi_input_buffer[SCPI_INPUT_BUFFER_LENGTH];
#define SCPI_ERROR_QUEUE_SIZE 17
scpi_error_t scpi_error_queue_data[SCPI_ERROR_QUEUE_SIZE];
scpi_t scpi_context;

//#define SCPI_IDN1 "VANHEUSDEN"
#define SCPI_IDN1 "Rigol Technologies"
#define SCPI_IDN2 "DG1022Z"
#define SCPI_IDN3 "DG1ZA000000001"
#define SCPI_IDN4 "03.01.12"

#define SAMPLE_RATE 48000

AvahiEntryGroup *group = nullptr;

void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata)
{
	if (state == AVAHI_CLIENT_S_RUNNING) {
		if (!(group = avahi_entry_group_new(c, nullptr, nullptr))) {
			fprintf(stderr, "avahi_entry_group_new() failed: %s\n", avahi_strerror(avahi_client_errno(c)));
			return;
		}

		int ret = 0;

		if ((ret = avahi_entry_group_add_service(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AvahiPublishFlags(0), "funcgen-scpi", "_scpi-raw._tcp", nullptr, nullptr, *(int *)userdata, nullptr)) < 0) {
			fprintf(stderr, "Failed to add service: %s\n", avahi_strerror(ret));
			return;
		}

		if ((ret = avahi_entry_group_commit(group)) < 0) {
			fprintf(stderr, "Failed to commit entry group: %s\n", avahi_strerror(ret));
			return;
		}
	}
}

size_t SCPI_Write(scpi_t * context, const char * data, size_t len) {
	if (context->user_context != NULL) {
		int fd = ((audio_dev_t *)context->user_context)->fd;

		int state = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		fprintf(stderr, "SEND: %s\n", std::string(data, len).c_str());

		return write(fd, data, len);
	}

	return 0;
}

scpi_result_t SCPI_Flush(scpi_t * context) {
	if (context->user_context != NULL) {
		int fd = ((audio_dev_t *)context->user_context)->fd;

		int state = 0;
		setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
	}

	return SCPI_RES_OK;
}

int SCPI_Error(scpi_t * context, int_fast16_t err) {
	fprintf(stderr, "**ERROR: %d, \"%s\"\r\n", (int16_t) err, SCPI_ErrorTranslate(err));
	return 0;
}

scpi_result_t SCPI_Control(scpi_t * context, scpi_ctrl_name_t ctrl, scpi_reg_val_t val) {
	if (SCPI_CTRL_SRQ == ctrl)
		fprintf(stderr, "**SRQ: 0x%X (%d)\r\n", val, val);
	else
		fprintf(stderr, "**CTRL %02x: 0x%X (%d)\r\n", ctrl, val, val);

	return SCPI_RES_OK;
}

scpi_result_t SCPI_Reset(scpi_t * context) {
	fprintf(stderr, "**Reset\r\n");

	return SCPI_RES_OK;
}

scpi_interface_t scpi_interface = {
	/*.error = */ SCPI_Error,
	/*.write = */ SCPI_Write,
	/*.control = */ SCPI_Control,
	/*.flush = */ SCPI_Flush,
	/*.reset = */ SCPI_Reset,
};

static int createServer(int port)
{
	struct sockaddr_in servaddr { 0 };

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket() failed");
		exit(-1);
	}

	int on = 1;
	int rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof (on));
	if (rc == -1) {
		perror("setsockopt() failed");
		close(fd);
		exit(-1);
	}

	rc = bind(fd, (struct sockaddr *) &servaddr, sizeof (servaddr));
	if (rc == -1) {
		perror("bind() failed");
		close(fd);
		exit(-1);
	}

	rc = listen(fd, 1);
	if (rc == -1) {
		perror("listen() failed");
		close(fd);
		exit(-1);
	}

	return fd;
}

static int waitServer(int fd) {
	fd_set fds;
	struct timeval timeout;
	int rc;
	int max_fd;

	FD_ZERO(&fds);
	max_fd = fd;
	FD_SET(fd, &fds);

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	rc = select(max_fd + 1, &fds, NULL, NULL, &timeout);

	return rc;
}

void on_process(void *userdata)
{
	audio_dev_t *const ad = (audio_dev_t *)userdata;

	int stride = 0, period_size = 0;
	struct pw_buffer *b = nullptr;
	struct spa_buffer *buf = nullptr;
	int16_t *dst = nullptr;
	double *temp_buffer = nullptr;
	void *out = nullptr;

	std::unique_lock<std::mutex> lck(ad->lock);

	if ((b = pw_stream_dequeue_buffer(ad->stream)) == nullptr) {
		pw_log_warn("out of buffers: %m");
		dolog("out of buffers: %s\n", strerror(errno));
		goto fail;
	}

	buf = b->buffer;

	stride = sizeof(int16_t) * ad->n_channels;
	period_size = std::min(buf->datas[0].maxsize / stride, ad->sample_rate / 75);

	temp_buffer = new double[ad->n_channels * period_size];

	try {
		for(int i=0; i<period_size; i++) {
			size_t o = i * ad->n_channels;

			memset(&temp_buffer[o], 0x00, sizeof(double) * ad->n_channels);

			double c = 0;
			const double base_mul = 2 * M_PI / ad->sample_rate;

			for(auto s : ad->freqs) {
				if (!s.enabled)
					continue;

				double v = sin(s.freq * ad->offset * base_mul) * s.amp + s.offset;

				if (s.type == S_SIN)
					c += v;
				else if (s.type == S_SQUARE)
					c += v >= 0 ? 1 : -1;
			}

			ad->offset++;

			for(int ch=0; ch < ad->n_channels; ch++) {
				temp_buffer[o + ch] += c;

				if (ad->cm == CM_CLIP) {
					if (temp_buffer[o + ch] < -1)
						temp_buffer[o + ch] = -1;
					else if (temp_buffer[o + ch] > 1)
						temp_buffer[o + ch] = 1;
				}
				else if (ad->cm == CM_ATAN) {
					temp_buffer[o + ch] = atan(temp_buffer[o + ch]) / M_PI;
				}
				else if (ad->cm == CM_TANH) {
					temp_buffer[o + ch] = tanh(temp_buffer[o + ch]);
				}
				else if (ad->cm == CM_DIV) {
					if (!ad->freqs.empty())
						temp_buffer[o + ch] /= ad->freqs.size();
				}
				else {
					// CM_AS_IS
				}
			}
		}
	}
	catch(...) {
		printf(" *** EXCEPTION ***\n");
	}

	if (ad->freqs.empty())
		ad->offset = 0;

	lck.unlock();

	if (ad->bits == 16) {
		short *const io_buffer = new short[ad->n_channels * period_size];
		out = io_buffer;

		for(int i=0; i<ad->n_channels * period_size; i++)
			io_buffer[i] = temp_buffer[i] * 32767.0;
	}
	else {
		int32_t *const io_buffer = new int32_t[ad->n_channels * period_size];
		out = io_buffer;

		double mul = 1677215.0;
		if (ad->bits == 32)
			mul = 2147483647.0;

		for(int i=0; i<ad->n_channels * period_size; i++)
			io_buffer[i] = temp_buffer[i] * mul;
	}

again:
	if ((dst = (int16_t *)buf->datas[0].data) == nullptr) {
		printf("fail\n");
		goto fail;
	}

	memcpy(dst, out, period_size * ad->n_channels * sizeof(int16_t));

	buf->datas[0].chunk->offset = 0;
	buf->datas[0].chunk->stride = stride;
	buf->datas[0].chunk->size = period_size * stride;

	pw_stream_queue_buffer(ad->stream, b);

fail:
	if (ad->bits == 16)
		delete [] (short *)out;
	else
		delete [] (int32_t *)out;

	delete [] temp_buffer;
}

audio_dev_t * configure_pw(const int sr, const clip_method_t cm, const int bits)
{
	int err;
	audio_dev_t *const ad = new audio_dev_t;

	ad->n_channels = 2;

	ad->cm = cm;

	ad->sample_rate = sr;
	ad->bits = bits;

	printf("sample rate: %u\n", ad->sample_rate);

	ad->th = new std::thread([ad, sr]() {
			ad->b = SPA_POD_BUILDER_INIT(ad->buffer, sizeof(ad->buffer));

			ad->loop = pw_main_loop_new(nullptr);

			ad->stream_events = { 0 };
			ad->stream_events.version = PW_VERSION_STREAM_EVENTS;
			ad->stream_events.process = on_process;

			ad->stream = pw_stream_new_simple(
					pw_main_loop_get_loop(ad->loop),
					"funcgen-scpi",
					pw_properties_new(
						PW_KEY_MEDIA_TYPE, "Audio",
						PW_KEY_MEDIA_CATEGORY, "Playback",
						PW_KEY_MEDIA_ROLE, "Music",
						nullptr),
					&ad->stream_events,
					ad);

			ad->saiw.flags = 0;
			ad->saiw.format = SPA_AUDIO_FORMAT_S16;
			ad->saiw.channels = 2;
			ad->saiw.rate = sr;
			memset(ad->saiw.position, 0x00, sizeof ad->saiw.position);

			ad->params[0] = spa_format_audio_raw_build(&ad->b, SPA_PARAM_EnumFormat, &ad->saiw);

			pw_stream_connect(ad->stream,
					PW_DIRECTION_OUTPUT,
					PW_ID_ANY,
					pw_stream_flags(PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_RT_PROCESS),
					ad->params, 1);

			pw_main_loop_run(ad->loop);
	});

	return ad;
}

static scpi_result_t My_CoreTstQ(scpi_t * context)
{
	SCPI_ResultInt32(context, 0);  // all is fine

	return SCPI_RES_OK;
}

scpi_result_t SCPI_SystemCommTcpipControlQ(scpi_t * context)
{
	return SCPI_RES_ERR;
}

void grow_slots_vector(std::vector<slot_t> *const v, const size_t req_size)
{
	if (req_size >= v->size())
		v->resize(req_size + 1);
}

int get_ch_nr(scpi_t * context)
{
	int32_t chnr = 0;
	SCPI_CommandNumbers(context, &chnr, 1, 1);
	chnr--;  // starts at 1

	return chnr;
}

scpi_result_t SCPI_SourceApplyWave(scpi_t * context, const slot_type_t & type)
{
	fprintf(stderr, "SCPI_SourceApplyWave\n");
	audio_dev_t *adev = (audio_dev_t *)context->user_context;

	int32_t chnr = get_ch_nr(context);

	double freq = 0;
	if (!SCPI_ParamDouble(context, &freq, TRUE))
		return SCPI_RES_ERR;

	double amp = 0;
	if (!SCPI_ParamDouble(context, &amp, TRUE))
		return SCPI_RES_ERR;

	double offset = 0;
	if (!SCPI_ParamDouble(context, &offset, TRUE))
		return SCPI_RES_ERR;

	// TODO: phase

	adev->lock.lock();

	grow_slots_vector(&adev->freqs, chnr);

	adev->freqs.at(chnr).freq   = freq;
	adev->freqs.at(chnr).amp    = amp;
	adev->freqs.at(chnr).offset = offset;
	adev->freqs.at(chnr).type   = type;

	adev->lock.unlock();

	return SCPI_RES_OK;
}

scpi_result_t SCPI_SourceApplySinusoid(scpi_t * context)
{
	return SCPI_SourceApplyWave(context, S_SIN);
}

scpi_result_t SCPI_SourceApplySquareWave(scpi_t * context)
{
	return SCPI_SourceApplyWave(context, S_SQUARE);
}

scpi_result_t SCPI_OutputState(scpi_t * context)
{
	fprintf(stderr, "SCPI_OutputState\n");
	audio_dev_t *adev = (audio_dev_t *)context->user_context;

	int32_t chnr = get_ch_nr(context);

	bool ena = 0;
	if (!SCPI_ParamBool(context, &ena, TRUE))
		return SCPI_RES_ERR;

	adev->lock.lock();

	grow_slots_vector(&adev->freqs, chnr);

	adev->freqs.at(chnr).enabled = ena;

	adev->lock.unlock();

	return SCPI_RES_OK;
}

scpi_result_t SCPI_OutputStateQ(scpi_t * context)
{
	fprintf(stderr, "SCPI_OutputStateQ\n");
	audio_dev_t *adev = (audio_dev_t *)context->user_context;

	int32_t chnr = get_ch_nr(context);

	adev->lock.lock();

	grow_slots_vector(&adev->freqs, chnr);

	bool state = adev->freqs.at(chnr).enabled;

	adev->lock.unlock();

	SCPI_ResultMnemonic(context, state ? "ON" : "OFF");

	return SCPI_RES_OK;
}

static scpi_result_t SCPI_SourceQ(scpi_t * context)
{
	fprintf(stderr, "SCPI_SourceQ\n");
	audio_dev_t *adev = (audio_dev_t *)context->user_context;

	int32_t chnr = get_ch_nr(context);

	adev->lock.lock();

	grow_slots_vector(&adev->freqs, chnr);

	SCPI_ResultMnemonic(context, "SIN");
	SCPI_ResultDouble(context, adev->freqs.at(chnr).freq);
	SCPI_ResultDouble(context, adev->freqs.at(chnr).amp);
	SCPI_ResultDouble(context, adev->freqs.at(chnr).offset);
	SCPI_ResultDouble(context, 0.0);  // phase

	adev->lock.unlock();

	return SCPI_RES_OK;
}

scpi_result_t SCPI_SourceFreq(scpi_t * context)
{
	fprintf(stderr, "SCPI_SourceFreq\n");
	audio_dev_t *adev = (audio_dev_t *)context->user_context;

	int32_t chnr = get_ch_nr(context);

	double freq = 0;
	if (!SCPI_ParamDouble(context, &freq, TRUE))
		return SCPI_RES_ERR;

	adev->lock.lock();

	grow_slots_vector(&adev->freqs, chnr);

	adev->freqs.at(chnr).freq = freq;

	adev->lock.unlock();

	return SCPI_RES_OK;
}

scpi_result_t SCPI_SourceAmpl(scpi_t * context)
{
	fprintf(stderr, "SCPI_SourceAmpl\n");
	audio_dev_t *adev = (audio_dev_t *)context->user_context;

	int32_t chnr = get_ch_nr(context);

	double amp = 0;
	if (!SCPI_ParamDouble(context, &amp, TRUE))
		return SCPI_RES_ERR;

	adev->lock.lock();

	grow_slots_vector(&adev->freqs, chnr);

	adev->freqs.at(chnr).amp = amp;

	adev->lock.unlock();

	return SCPI_RES_OK;
}

scpi_result_t SCPI_SourceOffset(scpi_t * context)
{
	fprintf(stderr, "SCPI_SourceOffset\n");
	audio_dev_t *adev = (audio_dev_t *)context->user_context;

	int32_t chnr = get_ch_nr(context);

	double offset = 0;
	if (!SCPI_ParamDouble(context, &offset, TRUE))
		return SCPI_RES_ERR;

	adev->lock.lock();

	grow_slots_vector(&adev->freqs, chnr);

	adev->freqs.at(chnr).offset = offset;

	adev->lock.unlock();

	return SCPI_RES_OK;
}

static scpi_result_t SCPI_CounterState(scpi_t * context)
{
	SCPI_ResultInt32(context, 0);  // all is fine

	return SCPI_RES_OK;
}

static scpi_result_t SCPI_CounterMeasureQ(scpi_t * context)
{
	fprintf(stderr, "SCPI_CounterMeasureQ\n");

	SCPI_ResultDouble(context, 0.0);  // frequency
	SCPI_ResultDouble(context, 0.0);  // period
	SCPI_ResultDouble(context, 0.0);  // duty cycle
	SCPI_ResultDouble(context, 0.0);  // positive pulse width
	SCPI_ResultDouble(context, 0.0);  // negative pulse width

	return SCPI_RES_OK;
}

const scpi_command_t scpi_commands[] = {
	/* IEEE Mandated Commands (SCPI std V1999.0 4.1.1) */
	{"*CLS", SCPI_CoreCls, 0},
	{"*ESE", SCPI_CoreEse, 0},
	{"*ESE?", SCPI_CoreEseQ, 0},
	{"*ESR?", SCPI_CoreEsrQ, 0},
	{"*IDN?", SCPI_CoreIdnQ, 0},
	{"*OPC", SCPI_CoreOpc, 0},
	{"*OPC?", SCPI_CoreOpcQ, 0},
	{"*RST", SCPI_CoreRst, 0},
	{"*SRE", SCPI_CoreSre, 0},
	{"*SRE?", SCPI_CoreSreQ, 0},
	{"*STB?", SCPI_CoreStbQ, 0},
	{"*TST?", My_CoreTstQ, 0},
	{"*WAI", SCPI_CoreWai, 0},

	/* Required SCPI commands (SCPI std V1999.0 4.2.1) */
	{"SYSTem:ERRor[:NEXT]?", SCPI_SystemErrorNextQ, 0},
	{"SYSTem:ERRor:COUNt?", SCPI_SystemErrorCountQ, 0},
	{"SYSTem:VERSion?", SCPI_SystemVersionQ, 0},

	{"STATus:QUEStionable[:EVENt]?", SCPI_StatusQuestionableEventQ, 0},
	{"STATus:QUEStionable:ENABle", SCPI_StatusQuestionableEnable, 0},
	{"STATus:QUEStionable:ENABle?", SCPI_StatusQuestionableEnableQ, 0},

	{"SYSTem:COMMunication:TCPIP:CONTROL?", SCPI_SystemCommTcpipControlQ, 0},

	{"SOURce#:APPLy:SINusoid", SCPI_SourceApplySinusoid, 0},
	{"SOURce#:APPLy:SQUare", SCPI_SourceApplySquareWave, 0},
	{"OUTPut#[:STATe]", SCPI_OutputState, 0},
	{"SOURce#:APPL?", SCPI_SourceQ, 0},
	{"SOURce#:FREQuency", SCPI_SourceFreq, 0},
	{"SOURce#:VOLTage", SCPI_SourceAmpl, 0},
	{"SOURce#:VOLTage:OFFSet", SCPI_SourceOffset, 0},
	{"COUNter[:STATe]?", SCPI_CounterState, 0},
	{"OUTPut#[:STATe]?", SCPI_OutputStateQ, 0},
	{"COUNter:MEASure?", SCPI_CounterMeasureQ, 0},

	SCPI_CMD_LIST_END
};

int main(int argc, char *argv[])
{
	printf("funcgen-scpi v1.0, (C) 2016-2021 by folkert@vanheusden.com\n\n");

	signal(SIGPIPE, SIG_IGN);

	pw_init(&argc, &argv);

	audio_dev_t *adev = configure_pw(SAMPLE_RATE, CM_DIV, 16);

	dolog("Audio thread started\n");

	char smbuffer[128] { 0 };

	SCPI_Init(&scpi_context,
			scpi_commands,
			&scpi_interface,
			scpi_units_def,
			SCPI_IDN1, SCPI_IDN2, SCPI_IDN3, SCPI_IDN4,
			scpi_input_buffer, SCPI_INPUT_BUFFER_LENGTH,
			scpi_error_queue_data, SCPI_ERROR_QUEUE_SIZE);

	scpi_context.user_context = adev;

	int base_port = 5025;
	int listenfd = createServer(base_port);

	AvahiSimplePoll *simple_poll = avahi_simple_poll_new();

	int error = 0;
	AvahiClient *client = avahi_client_new(avahi_simple_poll_get(simple_poll), AvahiClientFlags(0), client_callback, &base_port, &error);
	if (!client) {
		fprintf(stderr, "Failed to create AVAHI client: %s\n", avahi_strerror(error));
		return 1;
	}

	std::thread *t_avahi = new std::thread([simple_poll]() { avahi_simple_poll_loop(simple_poll); });

	for(;;) {
		int flag = 1;
		struct sockaddr_in cliaddr;
		socklen_t clilen = sizeof (cliaddr);

		int clifd = accept(listenfd, (struct sockaddr *) &cliaddr, &clilen);
		if (clifd == -1)
			continue;

		printf("Connection established %s\r\n", inet_ntoa(cliaddr.sin_addr));

		adev->fd = clifd;

		setsockopt(clifd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

		for(;;) {
			int rc = waitServer(clifd);
			if (rc == -1) { /* failed */
				perror("  recv() failed");
				break;
			}
			if (rc == 0) { /* timeout */
				SCPI_Input(&scpi_context, NULL, 0);
			}
			if (rc > 0) { /* something to read */
				rc = recv(clifd, smbuffer, sizeof (smbuffer), 0);
				if (rc == -1) {
					if (errno != EWOULDBLOCK) {
						perror("  recv() failed");
						break;
					}
				} else if (rc == 0) {
					printf("Connection closed\r\n");
					break;
				} else {
					printf("recv: %s\n", std::string(smbuffer, rc).c_str());
					SCPI_Input(&scpi_context, smbuffer, rc);
				}
			}
		}

		close(clifd);
	}

#if 0
	adev->lock.lock();

	adev->freqs.push_back(440);
	adev->freqs.push_back(1000);

	adev->lock.unlock();

	sleep(2);
#endif

	pw_stream_destroy(adev->stream);
	pw_main_loop_destroy(adev->loop);

	return 0;
}
