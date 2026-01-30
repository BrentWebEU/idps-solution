import { Routes } from '@angular/router';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { PentestComponent } from './components/pentest/pentest.component';

// Route configuratie voor de applicatie
// Standaard route leidt naar het dashboard
export const routes: Routes = [
  {
    path: '',
    component: DashboardComponent,
    title: 'IDPS Controle Paneel'
  },
  {
    path: 'dashboard',
    component: DashboardComponent,
    title: 'IDPS Controle Paneel'
  },
  {
    path: 'pentest',
    component: PentestComponent,
    title: 'Penetration Test Management'
  }
];
