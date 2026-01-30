import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, throwError } from 'rxjs';

// Interface voor container status informatie
export interface ContainerStatus {
  id: string;
  name: string;
  status: string;
  state: string;
  running: boolean;
}

// Interface voor API responses
export interface ApiResponse {
  success: boolean;
  message: string;
  data?: any;
}

// Interface voor exec commando response
export interface ExecResponse {
  command: string;
  stdout: string;
  stderr: string;
}

// Interface voor logs response
export interface LogsResponse {
  logs: string;
}

// Service voor communicatie met de IDPS API
// Deze service handelt alle HTTP requests af naar de Rust backend
@Injectable({
  providedIn: 'root'
})
export class IdpsService {
  // Base URL voor de API - gebruikt proxy configuratie in development
  // In development mode wordt dit via proxy.conf.json doorgestuurd naar localhost:8080
  // In production kan dit worden aangepast naar de productie API URL
  private readonly apiUrl = '/api';

  constructor(private http: HttpClient) {}

  // Haal de status op van de Suricata container
  getStatus(): Observable<ApiResponse> {
    return this.http.get<ApiResponse>(`${this.apiUrl}/status`).pipe(
      catchError(error => {
        console.error('Fout bij ophalen status:', error);
        return throwError(() => error);
      })
    );
  }

  // Start de Suricata container
  startSuricata(): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/suricata/start`, {}).pipe(
      catchError(error => {
        console.error('Fout bij starten Suricata:', error);
        return throwError(() => error);
      })
    );
  }

  // Stop de Suricata container
  stopSuricata(): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/suricata/stop`, {}).pipe(
      catchError(error => {
        console.error('Fout bij stoppen Suricata:', error);
        return throwError(() => error);
      })
    );
  }

  // Herstart de Suricata container
  restartSuricata(): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/suricata/restart`, {}).pipe(
      catchError(error => {
        console.error('Fout bij herstarten Suricata:', error);
        return throwError(() => error);
      })
    );
  }

  // Voer een commando uit in de Suricata container
  executeCommand(command: string, args: string[] = []): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/suricata/exec`, {
      command,
      args
    }).pipe(
      catchError(error => {
        console.error('Fout bij uitvoeren commando:', error);
        return throwError(() => error);
      })
    );
  }

  // Haal de logs op van de Suricata container
  getLogs(): Observable<ApiResponse> {
    return this.http.get<ApiResponse>(`${this.apiUrl}/suricata/logs`).pipe(
      catchError(error => {
        console.error('Fout bij ophalen logs:', error);
        return throwError(() => error);
      })
    );
  }
<<<<<<< HEAD
=======

  // PCAP Analysis Methods
  analyzePcap(pcapFile: string, options?: any): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/pcap/analyze`, {
      pcap_file: pcapFile,
      analysis_options: options
    }).pipe(
      catchError(error => {
        console.error('Fout bij analyseren PCAP:', error);
        return throwError(() => error);
      })
    );
  }

  getFindings(): Observable<ApiResponse> {
    return this.http.get<ApiResponse>(`${this.apiUrl}/pcap/findings`).pipe(
      catchError(error => {
        console.error('Fout bij ophalen findings:', error);
        return throwError(() => error);
      })
    );
  }

  // Rule Management Methods
  generateRule(finding: any): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/rules/generate`, finding).pipe(
      catchError(error => {
        console.error('Fout bij genereren regel:', error);
        return throwError(() => error);
      })
    );
  }

  listRules(): Observable<ApiResponse> {
    return this.http.get<ApiResponse>(`${this.apiUrl}/rules/list`).pipe(
      catchError(error => {
        console.error('Fout bij ophalen regels:', error);
        return throwError(() => error);
      })
    );
  }

  activateRule(ruleFile: string): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/rules/activate`, {
      rule_file: ruleFile
    }).pipe(
      catchError(error => {
        console.error('Fout bij activeren regel:', error);
        return throwError(() => error);
      })
    );
  }

  deactivateRule(ruleFile: string): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/rules/deactivate`, {
      rule_file: ruleFile
    }).pipe(
      catchError(error => {
        console.error('Fout bij deactiveren regel:', error);
        return throwError(() => error);
      })
    );
  }

  testRules(pcapFile: string, ruleFile?: string): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/rules/test`, {
      pcap_file: pcapFile,
      rule_file: ruleFile
    }).pipe(
      catchError(error => {
        console.error('Fout bij testen regels:', error);
        return throwError(() => error);
      })
    );
  }
>>>>>>> 19bcb69 (Add scripts for external pentest workflow and vulnerability scanning)
}
