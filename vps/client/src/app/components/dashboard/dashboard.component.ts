import { Component, OnInit, signal, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IdpsService, ContainerStatus } from '../../services/idps.service';

// Dashboard component voor IDPS controle
// Dit is het hoofdcomponent voor het beheren van Suricata
@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css'
})
export class DashboardComponent implements OnInit {
  // Status van de Suricata container
  containerStatus = signal<ContainerStatus | null>(null);
  
  // Laad status voor UI feedback
  isLoading = signal<boolean>(false);
  
  // Foutmeldingen
  errorMessage = signal<string | null>(null);
  
  // Logs van de container
  logs = signal<string>('');
  
  // Commando input voor handmatige commando's
  commandInput = signal<string>('suricata');
  argsInput = signal<string>('-V');
  
  // Exec output
  execOutput = signal<{ stdout: string; stderr: string } | null>(null);

  constructor(private idpsService: IdpsService) {
    // Effect om automatisch status te verversen wanneer container status verandert
    effect(() => {
      const status = this.containerStatus();
      if (status) {
        console.log('Container status bijgewerkt:', status);
      }
    });
  }

  // Initialisatie - haal status op bij het laden van de component
  ngOnInit(): void {
    this.refreshStatus();
  }

  // Ververs de status van de container
  refreshStatus(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    
    this.idpsService.getStatus().subscribe({
      next: (response) => {
        if (response.success && response.data) {
          this.containerStatus.set(response.data as ContainerStatus);
        } else {
          this.errorMessage.set(response.message || 'Onbekende fout');
        }
        this.isLoading.set(false);
      },
      error: (error) => {
        let errorMsg = 'Onbekende fout';
        if (error.status === 0) {
          errorMsg = 'Kan geen verbinding maken met de server. Controleer of de API server draait op poort 8080.';
        } else if (error.status === 404) {
          errorMsg = 'API endpoint niet gevonden. Controleer de server configuratie.';
        } else if (error.status >= 500) {
          errorMsg = `Server fout (${error.status}): ${error.message || 'Interne server fout'}`;
        } else {
          errorMsg = error.message || `HTTP ${error.status}: ${error.error?.message || 'Onbekende fout'}`;
        }
        this.errorMessage.set('Fout bij ophalen status: ' + errorMsg);
        this.isLoading.set(false);
      }
    });
  }

  // Start de Suricata container
  startSuricata(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    
    this.idpsService.startSuricata().subscribe({
      next: (response) => {
        if (response.success) {
          // Wacht even en ververs dan de status
          setTimeout(() => this.refreshStatus(), 1000);
        } else {
          this.errorMessage.set(response.message || 'Fout bij starten');
          this.isLoading.set(false);
        }
      },
      error: (error) => {
        this.errorMessage.set('Fout bij starten: ' + (error.message || 'Onbekende fout'));
        this.isLoading.set(false);
      }
    });
  }

  // Stop de Suricata container
  stopSuricata(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    
    this.idpsService.stopSuricata().subscribe({
      next: (response) => {
        if (response.success) {
          // Wacht even en ververs dan de status
          setTimeout(() => this.refreshStatus(), 1000);
        } else {
          this.errorMessage.set(response.message || 'Fout bij stoppen');
          this.isLoading.set(false);
        }
      },
      error: (error) => {
        this.errorMessage.set('Fout bij stoppen: ' + (error.message || 'Onbekende fout'));
        this.isLoading.set(false);
      }
    });
  }

  // Herstart de Suricata container
  restartSuricata(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    
    this.idpsService.restartSuricata().subscribe({
      next: (response) => {
        if (response.success) {
          // Wacht even en ververs dan de status
          setTimeout(() => this.refreshStatus(), 2000);
        } else {
          this.errorMessage.set(response.message || 'Fout bij herstarten');
          this.isLoading.set(false);
        }
      },
      error: (error) => {
        this.errorMessage.set('Fout bij herstarten: ' + (error.message || 'Onbekende fout'));
        this.isLoading.set(false);
      }
    });
  }

  // Haal logs op van de container
  loadLogs(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    
    this.idpsService.getLogs().subscribe({
      next: (response) => {
        if (response.success && response.data?.logs) {
          this.logs.set(response.data.logs);
        } else {
          this.errorMessage.set(response.message || 'Fout bij ophalen logs');
        }
        this.isLoading.set(false);
      },
      error: (error) => {
        this.errorMessage.set('Fout bij ophalen logs: ' + (error.message || 'Onbekende fout'));
        this.isLoading.set(false);
      }
    });
  }

  // Voer een commando uit in de container
  executeCommand(): void {
    const command = this.commandInput();
    const args = this.argsInput().split(' ').filter(arg => arg.length > 0);
    
    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.execOutput.set(null);
    
    this.idpsService.executeCommand(command, args).subscribe({
      next: (response) => {
        if (response.success && response.data) {
          this.execOutput.set({
            stdout: response.data.stdout || '',
            stderr: response.data.stderr || ''
          });
        } else {
          this.errorMessage.set(response.message || 'Fout bij uitvoeren commando');
        }
        this.isLoading.set(false);
      },
      error: (error) => {
        this.errorMessage.set('Fout bij uitvoeren commando: ' + (error.message || 'Onbekende fout'));
        this.isLoading.set(false);
      }
    });
  }
}
