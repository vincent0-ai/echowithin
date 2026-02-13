import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
    appId: 'xyz.echowithin.app',
    appName: 'EchoWithin',
    webDir: 'www',
    server: {
        url: 'https://blog.echowithin.xyz',
        androidScheme: 'https',
        allowNavigation: ['blog.echowithin.xyz']
    },
    android: {
        backgroundColor: '#FFFFFF',
        appendUserAgent: ' EchoWithinApp',
        buildOptions: {
            releaseType: 'AAB',
        }
    },
    plugins: {
        SplashScreen: {
            launchShowDuration: 3000,
            launchAutoHide: false,
            backgroundColor: '#FFFFFF',
            showSpinner: true,
            androidScaleType: 'CENTER_CROP'
        },
        StatusBar: {
            style: 'DARK',
            backgroundColor: '#FFFFFF'
        }
    }
};

export default config;
