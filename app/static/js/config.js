/**
 * Configuration de l'interface utilisateur
 */
const CONFIG = {
    // URL de l'API
    API_URL: '/api',
    
    // Paramètres de l'interface
    UI: {
        // Thème par défaut (light/dark)
        theme: 'dark',
        
        // Rafraîchissement automatique des données (en millisecondes)
        refreshInterval: 10000,
        
        // Nombre d'éléments par page dans les tableaux
        itemsPerPage: 10,
        
        // Afficher les notifications
        showNotifications: true,
        
        // Durée d'affichage des notifications (ms)
        notificationDuration: 5000
    },
    
    // Paramètres par défaut des règles
    DEFAULTS: {
        RULE: {
            action: 'allow',
            direction: 'both',
            protocol: 'tcp',
            port: '',
            source: 'any',
            destination: 'any',
            is_active: true
        },
        
        // Protocoles supportés
        PROTOCOLS: [
            { value: 'tcp', label: 'TCP' },
            { value: 'udp', label: 'UDP' },
            { value: 'icmp', label: 'ICMP' },
            { value: 'any', label: 'Tous' }
        ],
        
        // Actions possibles
        ACTIONS: [
            { value: 'allow', label: 'Autoriser', color: 'success' },
            { value: 'deny', label: 'Refuser', color: 'error' },
            { value: 'reject', label: 'Rejeter', color: 'warning' }
        ],
        
        // Directions possibles
        DIRECTIONS: [
            { value: 'in', label: 'Entrant' },
            { value: 'out', label: 'Sortant' },
            { value: 'both', label: 'Les deux' }
        ]
    },
    
    // Paramètres système
    SYSTEM: {
        // Services système à surveiller
        MONITOR_SERVICES: [
            'ufw',
            'nginx',
            'postgresql',
            'redis',
            'docker'
        ],
        
        // Chemins importants
        PATHS: {
            LOGS: '/var/log',
            CONFIG: '/etc',
            BACKUP: '/var/backups'
        }
    },
    
    // Paramètres de sécurité
    SECURITY: {
        // Force minimale du mot de passe
        PASSWORD_STRENGTH: {
            minLength: 8,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSpecialChars: true
        },
        
        // Durée de session (en minutes)
        SESSION_TIMEOUT: 30,
        
        // Tentatives de connexion avant blocage
        MAX_LOGIN_ATTEMPTS: 5
    },
    
    // Paramètres de journalisation
    LOGGING: {
        // Niveau de journalisation (debug, info, warn, error)
        level: 'info',
        
        // Journalisation dans la console
        console: true,
        
        // Journalisation dans un fichier
        file: true,
        
        // Chemin du fichier de log
        filePath: '/var/log/firewall-ui.log',
        
        // Taille maximale du fichier de log (en Mo)
        maxFileSize: 10
    }
};

// Export pour les modules ES
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CONFIG;
}
