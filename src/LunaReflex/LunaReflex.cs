using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace LunaReflex
{
    public partial class LunaReflex : ServiceBase
    {
        EventLog logger;

        public LunaReflex()
        {
            InitializeComponent();
            logger = new EventLog();
            if (!EventLog.SourceExists(ServiceName))
            {
                EventLog.CreateEventSource(ServiceName, ServiceName);
            }
            logger.Source = ServiceName;
            logger.Log = ServiceName;
        }

        protected override void OnStart(string[] args)
        {
            logger.WriteEntry("Starting " + ServiceName + "...", EventLogEntryType.Information);

            Timer timer = new Timer
            {
                Interval = 60000 // 60 seconds
            };
            timer.Elapsed += new ElapsedEventHandler(this.OnTimer);
            timer.Start();

            logger.WriteEntry("Started monitoring.", EventLogEntryType.Information);
        }

        protected override void OnStop()
        {
            logger.WriteEntry("Stopping " + ServiceName + "...", EventLogEntryType.Information);
        }

        public void OnTimer(object sender, ElapsedEventArgs args)
        {
            logger.WriteEntry("Ping!", EventLogEntryType.Information);
        }
    }
}
