import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
    appId: 'xyz.echowithin.app',
    appName: 'EchoWithin',
    webDir: 'www',
    server: {
        // Don't set 'url' here — the local bridge page (www/index.html)
        // handles connectivity checks and offline state before redirecting
        // to the live site. Setting url bypasses the bridge and causes
        // "Web page not available" + stuck splash screen when offline.
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
