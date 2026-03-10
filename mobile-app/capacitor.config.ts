import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
    appId: 'xyz.echowithin.app',
    appName: 'EchoWithin',
    webDir: 'www',
    server: {
        url: 'https://blog.echowithin.xyz',
        androidScheme: 'https',
        allowNavigation: ['blog.echowithin.xyz'],
        errorPath: 'offline.html',
        cleartext: true
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
            launchAutoHide: true,
            backgroundColor: '#FFFFFF',
            showSpinner: true,
            androidScaleType: 'CENTER_CROP'
        },
        CapacitorCookies: {
            enabled: true
        },
        StatusBar: {
            style: 'DARK',
            backgroundColor: '#FFFFFF'
        }
    }
};

export default config;
