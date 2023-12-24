using System.Diagnostics;
using System.Windows.Forms;

namespace Xpass
{
    public partial class Form1 : Form
    {
        private List<string> selectedFiles = [];
        public Form1()
        {
            InitializeComponent();
            ImproveDataGridView();
        }

        private void ImproveDataGridView()
        {

            // ���ø��н�����ɫ
            dataGridView1.RowsDefaultCellStyle.BackColor = Color.White;
            dataGridView1.AlternatingRowsDefaultCellStyle.BackColor = Color.LightGray;


            var indexColumn = new DataGridViewTextBoxColumn
            {
                Name = "IndexColumn",
                HeaderText = "���",
                Width = 40
            };
            indexColumn.HeaderCell.Style.WrapMode = DataGridViewTriState.False;

            var sessionPathColumn = new DataGridViewTextBoxColumn
            {
                Name = "SessionPathColumn",
                HeaderText = "�Ự·��",
                Width = 200
            };
            sessionPathColumn.HeaderCell.Style.WrapMode = DataGridViewTriState.False;

            var hostColumn = new DataGridViewTextBoxColumn
            {
                Name = "HostAddressColumn",
                HeaderText = "������ַ",
                Width = 110
            };
            hostColumn.HeaderCell.Style.WrapMode = DataGridViewTriState.False;

            var portColumn = new DataGridViewTextBoxColumn
            {
                Name = "PortColumn",
                HeaderText = "�˿�",
                Width = 50
            };
            portColumn.HeaderCell.Style.WrapMode = DataGridViewTriState.False;

            var usernameColumn = new DataGridViewTextBoxColumn
            {
                Name = "UsernameColumn",
                HeaderText = "�û���",
                Width = 60
            };
            usernameColumn.HeaderCell.Style.WrapMode = DataGridViewTriState.False;

            var passwordColumn = new DataGridViewTextBoxColumn
            {
                Name = "PasswordColumn",
                HeaderText = "����",
                Width = dataGridView1.Width - 2 - (dataGridView1.RowHeadersWidth + indexColumn.Width + sessionPathColumn.Width + hostColumn.Width + portColumn.Width + usernameColumn.Width)

            };
            passwordColumn.HeaderCell.Style.WrapMode = DataGridViewTriState.False;
            dataGridView1.Columns.AddRange(new DataGridViewTextBoxColumn[] { indexColumn, sessionPathColumn, hostColumn, portColumn, usernameColumn, passwordColumn });

        }

        private void SelectFilesButton_Click(object sender, EventArgs e)
        {
            // ����û������ "ȷ��" ��ť
            if (openFileDialog1.ShowDialog(this) == DialogResult.OK)
            {

                if (openFileDialog1.FileNames.Length > 0)
                {
                    pathRichTextBox.Clear();
                    selectedFiles.Clear();
                    // ��ȡ�û�ѡ����ļ�·��
                    selectedFiles.AddRange(openFileDialog1.FileNames);

                    // �������ÿ��Ԫ��д�� RichTextBox��ÿ��Ԫ��ռ��һ��
                    foreach (string element in selectedFiles)
                    {
                        pathRichTextBox.AppendText(element + Environment.NewLine);
                    }
                }

            }
        }

        private void SelectDirButton_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog1.ShowDialog(this) == DialogResult.OK)
            {
                if (!string.IsNullOrEmpty(folderBrowserDialog1.SelectedPath))
                {
                    // ��� RichTextBox
                    pathRichTextBox.Clear();
                    selectedFiles.Clear();
                    pathRichTextBox.AppendText(folderBrowserDialog1.SelectedPath);
                    selectedFiles = Xclass.GetXshFiles(folderBrowserDialog1.SelectedPath);

                }
            }
        }

        private void AddRowToDataGridView(List<object> rowData)
        {
            // �����µ���
            DataGridViewRow row = new DataGridViewRow();

            // ���ÿһ�еĵ�Ԫ��
            for (int i = 0; i < rowData.Count; i++)
            {
                DataGridViewCell cell = new DataGridViewTextBoxCell();
                cell.Value = rowData[i];
                if (i == 5 && rowData[i] == "ȷ���������Ƿ���ȷ��")
                {
                    cell.Style.ForeColor = Color.Red;
                }

                row.Cells.Add(cell);
            }

            // ������ӵ�DataGridView
            dataGridView1.Rows.Add(row);
        }

        private void DecryptButton_Click(object sender, EventArgs e)
        {
            if (selectedFiles.Count > 0)
            {
                string sid;
                if (masterPasswdTextBox.Text.Length > 0)
                {
                    sid = masterPasswdTextBox.Text;
                }
                else
                {
                    sid = Xclass.GetSid();
                }
                dataGridView1.Rows.Clear();
                int index = 1;
                foreach (string element in selectedFiles)
                {
                    var session = Xclass.FileParser(element, sid);
                    var error = "ȷ���������Ƿ���ȷ��";
                    if (!session.isok)
                    {
                        session.password = error;
                    }

                    AddRowToDataGridView(new List<object> { index, element, session.host, session.port, session.userName, session.password });

                    index++;
                }
            }
            else
            {
                MessageBox.Show(this, "��ѡ���ļ�����Ŀ¼��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void showPasswdCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (showPasswdCheckBox.Checked)
            {
                masterPasswdTextBox.PasswordChar = '\0';
            }
            else
            {
                masterPasswdTextBox.PasswordChar = '*';
            }
        }

    }
}
