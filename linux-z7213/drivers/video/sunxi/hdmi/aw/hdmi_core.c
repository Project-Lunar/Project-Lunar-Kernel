#include "hdmi_core.h"

__s32		hdmi_state = HDMI_State_Idle;
bool		video_enable = 0;
__u32		video_mode = HDMI720P_50;
__s32		cts_enable = 0;
__s32		hdcp_enable = 0;

HDMI_AUDIO_INFO audio_info;
__u8		EDID_Buf[1024];
__u8 		Device_Support_VIC[512];
__u8		isHDMI = 0;
__u8		YCbCr444_Support = 0;
__u32		rgb_only = 0;
__s32		HPD = 0;
__u32		hdmi_print = 0;

__u32		hdmi_pll = 0;//0:video pll 0; 1:video pll 1
__u32		hdmi_clk = 297000000;

disp_video_timing video_timing[] =
{
	//VIC				   PCLK    AVI_PR  X      Y      HT      HBP   HFP   HST    VT     VBP  VFP  VST h_pol v_pol int vac   trd
	{HDMI1440_480I,      13500000,  1,  720,   240,   858,   57,   19,   62,  525,   15,  4,  3,  0,   0,   1,   0,   0},
	{HDMI1440_576I,      13500000,  1,  720,   288,   864,   69,   12,   63,  625,   19,  2,  3,  0,   0,   1,   0,   0},
	{HDMI480P,           27000000,  0,  720,   480,   858,   60,   16,   62,  525,   30,  9,  6,  0,   0,   0,   0,   0},
	{HDMI576P,           27000000,  0,  720,   576,   864,   68,   12,   64,  625,   39,  5,  5,  0,   0,   0,   0,   0},
	{HDMI720P_50,        74250000,  0,  1280,  720,   1980,  220,  440,  40,  750,   20,  5,  5,  1,   1,   0,   0,   0},
	{HDMI720P_60,        74250000,  0,  1280,  720,   1650,  220,  110,  40,  750,   20,  5,  5,  1,   1,   0,   0,   0},
	{HDMI1080I_50,       74250000,  0,  1920,  540,   2640,  148,  528,  44,  1125,  15,  2,  5,  1,   1,   1,   0,   0},
	{HDMI1080I_60,       74250000,  0,  1920,  540,   2200,  148,  88,   44,  1125,  15,  2,  5,  1,   1,   1,   0,   0},
	{HDMI1080P_50,       148500000, 0,  1920,  1080,  2640,  148,  528,  44,  1125,  36,  4,  5,  1,   1,   0,   0,   0},
	{HDMI1080P_60,       148500000, 0,  1920,  1080,  2200,  148,  88,   44,  1125,  36,  4,  5,  1,   1,   0,   0,   0},
	{HDMI1080P_24,       74250000,  0,  1920,  1080,  2750,  148,  638,  44,  1125,  36,  4,  5,  1,   1,   0,   0,   0},
	{HDMI1080P_25,       74250000,  0,  1920,  1080,  2640,  148,  528,  44,  1125,  36,  4,  5,  0,   0,   0,   0,   0},
	{HDMI1080P_30,       74250000,  0,  1920,  1080,  2200,  148,  88,   44,  1125,  36,  4,  5,  0,   0,   0,   0,   0},
	{HDMI1080P_24_3D_FP, 148500000, 0,  1920,  2160,  2750,  148,  638,  44,  1125,  36,  4,  5,  1,   1,   0,   45,  1},
	{HDMI720P_50_3D_FP,  148500000, 0,  1280,  1440,  1980,  220,  440,  40,  750,   20,  5,  5,  1,   1,   0,   30,  1},
	{HDMI720P_60_3D_FP,  148500000, 0,  1280,  1440,  1650,  220,  110,  40,  750,   20,  5,  5,  1,   1,   0,   30,  1},
	{HDMI3840_2160P_30,  297000000, 0,  3840,  2160,  4400,  296,  176,  88,  2250,  72,  8, 10,  1,   1,   0,    0,  0},
	{HDMI3840_2160P_25,  297000000, 0,  3840,  2160,  5280,  296, 1056,  88,  2250,  72,  8, 10,  1,   1,   0,    0,  0},
};

__s32 hdmi_core_initial(void)
{
	hdmi_state	  = HDMI_State_Idle;
	video_mode	  = HDMI720P_50;
	memset(&audio_info,0,sizeof(HDMI_AUDIO_INFO));
	memset(Device_Support_VIC,0,sizeof(Device_Support_VIC));
	sunxi_set_reg_base(0xf0000000);
	api_set_func(hdmi_delay_us);
	video_enter_lp();

	return 0;
}

__s32 main_Hpd_Check(void)
{
	__s32 i,times;
	times	= 0;

	for(i=0;i<3;i++) {
		hdmi_delay_ms(200);
		if( sunxi_get_hpd())
			times++;
	}

	if(times == 3)
		return 1;
	else
		return 0;
}

__s32 hdmi_main_task_loop(void)
{
	static __u32 times = 0;

	HPD = main_Hpd_Check();
	if( !HPD )
	{
		if((times++) >= 10) {
			times = 0;
			__inf("unplug state\n");
		}
		if(hdmi_state > HDMI_State_Wait_Hpd) {
			__inf("plugout\n");
			hdmi_state = HDMI_State_Wait_Hpd;
			Hdmi_hpd_event();
			video_enter_lp();
		}
	}
	switch(hdmi_state) {
		case HDMI_State_Idle:
			hdmi_state = HDMI_State_Wait_Hpd;

		case HDMI_State_Wait_Hpd:
			if(HPD) {
				hdmi_state = HDMI_State_EDID_Parse;
				__inf("plugin\n");
			} else {
				return 0;
			}

		case HDMI_State_Rx_Sense:

		case HDMI_State_EDID_Parse:
			hdmi_state = HDMI_State_Wait_Video_config;
			ParseEDID();
			Hdmi_hpd_event();

		case HDMI_State_Wait_Video_config:
		case HDMI_State_Video_config:
			if(video_enable == 1) {
				video_config(video_mode);
				hdmi_state = 	HDMI_State_Audio_config;
			}
		case HDMI_State_Audio_config:
			audio_config();
			hdmi_state = 	HDMI_State_Playback;
		case HDMI_State_Playback:
			return 0;
		default:
			__wrn(" unkonwn hdmi state, set to idle\n");
			hdmi_state = HDMI_State_Idle;
			return 0;
	}
}

__s32 Hpd_Check(void)
{
	if(hdmi_state >= HDMI_State_Wait_Video_config)
		return 1;
	else
		return 0;
}

__s32 get_video_info(__s32 vic)
{
	__s32 i,count;
	count = sizeof(video_timing);
	for(i=0;i<count;i++) {
		if(vic == video_timing[i].vic)
		return i;
	}
	__wrn("can't find the video timing parameters\n");
	return -1;
}

__s32 get_audio_info(__s32 sample_rate)
{
	//ACR_N 32000 44100 48000 88200 96000 176400 192000
	//		4096  6272  6144  12544 12288  25088  24576
	__inf("sample_rate:%d in get_audio_info\n", sample_rate);

	switch(sample_rate) {
		case 32000 :{	audio_info.ACR_N = 4096 ;
			audio_info.CH_STATUS0 = (3 <<24);
			audio_info.CH_STATUS1 = 0x0000000b;
			break;}
		case 44100 :{	audio_info.ACR_N = 6272 ;
			audio_info.CH_STATUS0 = (0 <<24);
			audio_info.CH_STATUS1 = 0x0000000b;
			break;}
		case 48000 :{	audio_info.ACR_N = 6144 ;
			audio_info.CH_STATUS0 = (2 <<24);
			audio_info.CH_STATUS1 = 0x0000000b;
			break;}
		case 88200 :{	audio_info.ACR_N = 12544;
			audio_info.CH_STATUS0 = (8 <<24);
			audio_info.CH_STATUS1 = 0x0000000b;
			break;}
		case 96000 :{	audio_info.ACR_N = 12288;
			audio_info.CH_STATUS0 = (10<<24);
			audio_info.CH_STATUS1 = 0x0000000b;
			break;}
		case 176400:{	audio_info.ACR_N = 25088;
			audio_info.CH_STATUS0 = (12<<24);
			audio_info.CH_STATUS1 = 0x0000000b;
			break;}
		case 192000:{	audio_info.ACR_N = 24576;
			audio_info.CH_STATUS0 = (14<<24);
			audio_info.CH_STATUS1 = 0x0000000b;
			break;}
		default:	{	__wrn("un-support sample_rate,value=%d\n",sample_rate);
				return -1;}
	}

	if((video_mode == HDMI1440_480I) || (video_mode == HDMI1440_576I) ||
		/*(video_mode == HDMI480P)	 || */(video_mode == HDMI576P)) {
		audio_info.CTS =   ((27000000/100) *(audio_info.ACR_N /128)) / (sample_rate/100);
	} else if( (video_mode == HDMI720P_50 )||(video_mode == HDMI720P_60 ) ||
				 (video_mode == HDMI1080I_50)||(video_mode == HDMI1080I_60) ||
				 (video_mode == HDMI1080P_24)||(video_mode == HDMI1080P_25) ||
				 (video_mode == HDMI1080P_30)) {
		audio_info.CTS =   ((74250000/100) *(audio_info.ACR_N /128)) / (sample_rate/100);
	} else if( (video_mode == HDMI1080P_50)||(video_mode == HDMI1080P_60)	   ||
			(video_mode == HDMI1080P_24_3D_FP)||(video_mode == HDMI720P_50_3D_FP) ||
			(video_mode == HDMI720P_60_3D_FP) ) {
		audio_info.CTS =   ((148500000/100) *(audio_info.ACR_N /128)) / (sample_rate/100);
	} else {
		__wrn("unkonwn video format when configure audio\n");
		return -1;
	}
	__inf("audio CTS calc:%d\n",audio_info.CTS);
	return 0;
}

__s32 video_config(__u32 vic)
{
	sunxi_video_config(vic);

	return 0;
}

__s32 video_enter_lp(void)
{
	sunxi_hdmi_enter_lp();

	return 0;
}

__s32 audio_config(void)
{
	struct sunxi_audio_para para;
	__inf("audio_config, sample_rate:%d\n", audio_info.sample_rate);
	if(!audio_info.audio_en) {
		return 0;
	}
	para.sample_rate = audio_info.sample_rate;
	para.channel_num = audio_info.channel_num;
	para.data_raw = audio_info.data_raw;
	para.sample_bit = audio_info.sample_bit;

	sunxi_audio_config(&para);
	return 0;
}

